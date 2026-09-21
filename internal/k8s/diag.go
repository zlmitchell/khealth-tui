package k8s

import (
	"context"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/zlmitchell/khealth-tui/internal/strutil"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Diag runs the API calls the TUI depends on and prints what each returns,
// so permission or connectivity problems can be seen without the UI.
func (c *Client) Diag(ctx context.Context, w io.Writer) {
	fmt.Fprintf(w, "context %s  server %s\n\n", c.Context, c.Host)
	if v, err := c.CS.Discovery().ServerVersion(); err == nil {
		fmt.Fprintf(w, "server version: %s\n", v.GitVersion)
	} else {
		fmt.Fprintf(w, "server version: ERROR %v\n", err)
	}
	nodes, err := c.CS.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		fmt.Fprintf(w, "list nodes: ERROR %v\n", err)
		return
	}
	pvcs, _ := c.CS.CoreV1().PersistentVolumeClaims("").List(ctx, metav1.ListOptions{})
	bound := 0
	for _, p := range pvcs.Items {
		if p.Status.Phase == corev1.ClaimBound {
			bound++
		}
	}
	fmt.Fprintf(w, "nodes: %d   PVCs: %d (%d bound)\n\n", len(nodes.Items), len(pvcs.Items), bound)
	if pvs, err := c.CS.CoreV1().PersistentVolumes().List(ctx, metav1.ListOptions{}); err == nil {
		kinds := map[string]int{}
		fmt.Fprintln(w, "== persistent volumes (source type decides whether the kubelet can report usage) ==")
		for i := range pvs.Items {
			pv := &pvs.Items[i]
			src, path := pvSource(pv)
			kinds[src]++
			if i < 30 {
				claim := ""
				if pv.Spec.ClaimRef != nil {
					claim = pv.Spec.ClaimRef.Namespace + "/" + pv.Spec.ClaimRef.Name
				}
				fmt.Fprintf(w, "  %-45s %-10s %-45s %s %s\n", pv.Name, src, claim, pv.Spec.StorageClassName, path)
			}
		}
		fmt.Fprintf(w, "  by source: %v\n\n", kinds)
	}

	pods, _ := c.CS.CoreV1().Pods("").List(ctx, metav1.ListOptions{})
	mounted := map[string][]string{} // node -> ns/claim
	for i := range pods.Items {
		p := &pods.Items[i]
		if p.Status.Phase != corev1.PodRunning {
			continue
		}
		for _, v := range p.Spec.Volumes {
			if v.PersistentVolumeClaim != nil {
				mounted[p.Spec.NodeName] = append(mounted[p.Spec.NodeName], p.Namespace+"/"+v.PersistentVolumeClaim.ClaimName)
			}
		}
	}

	fmt.Fprintln(w, "== per node: nodes/proxy configz, stats/summary (PVC usage) ==")
	for i := range nodes.Items {
		n := &nodes.Items[i]
		fmt.Fprintf(w, "\n[%s]  %s  claims mounted by running pods here: %d\n", n.Name, NodeAddress(n, "InternalIP"), len(mounted[n.Name]))
		t := time.Now()
		if _, err := c.kubeletConfigz(ctx, n.Name); err != nil {
			fmt.Fprintf(w, "  configz:       ERROR %v\n", strutil.FirstLine(err.Error()))
		} else {
			fmt.Fprintf(w, "  configz:       ok (%s)\n", time.Since(t).Round(time.Millisecond))
		}
		t = time.Now()
		raw, err := c.CS.CoreV1().RESTClient().Get().Resource("nodes").Name(n.Name).SubResource("proxy").Suffix("stats/summary").Do(ctx).Raw()
		if err != nil {
			fmt.Fprintf(w, "  stats/summary: ERROR %v\n", strutil.FirstLine(err.Error()))
			if len(raw) > 0 {
				fmt.Fprintf(w, "                 body: %s\n", strutil.FirstLine(string(raw)))
			}
			continue
		}
		if dump := os.Getenv("KHT_DIAG_DUMP"); dump != "" {
			_ = os.WriteFile(dump+"."+n.Name+".json", raw, 0o600)
		}
		usage, perr := c.kubeletVolumeStats(ctx, n.Name)
		fmt.Fprintf(w, "  stats/summary: ok, %d bytes (%s); parsed PVC volumes: %d", len(raw), time.Since(t).Round(time.Millisecond), len(usage))
		if perr != nil {
			fmt.Fprintf(w, " parse error: %v", perr)
		}
		fmt.Fprintln(w)
		keys := make([]string, 0, len(usage))
		for k := range usage {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			u := usage[k]
			fmt.Fprintf(w, "    %-50s used %s of %s (%.0f%%) pod %s\n", k, strutil.HumanBytes(float64(u.Used)), strutil.HumanBytes(float64(u.Capacity)), u.UsedPct(), u.Pod)
		}
		if len(usage) == 0 && len(mounted[n.Name]) > 0 {
			fmt.Fprintf(w, "    NOTE: pods here mount %s but the kubelet reported no pvcRef volumes\n", strings.Join(mounted[n.Name], ", "))
			if strings.Contains(string(raw), `"pvcRef"`) {
				fmt.Fprintln(w, "    (raw response does contain pvcRef entries: parsing issue, please report)")
			} else {
				snippet := string(raw)
				if i := strings.Index(snippet, `"volume"`); i >= 0 && len(snippet) > i+300 {
					snippet = snippet[i : i+300]
				}
				fmt.Fprintf(w, "    raw volume sample: %s\n", strutil.FirstLine(snippet))
			}
		}
	}

	fmt.Fprintln(w, "\n== metrics.k8s.io ==")
	if m, err := c.nodeMetrics(ctx); err != nil {
		fmt.Fprintf(w, "  ERROR %v\n", strutil.FirstLine(err.Error()))
	} else {
		fmt.Fprintf(w, "  ok, %d nodes\n", len(m))
	}

	fmt.Fprintln(w, "\n== pods/exec into etcd static pod ==")
	found := false
	for i := range pods.Items {
		p := &pods.Items[i]
		if p.Namespace == "kube-system" && p.Labels["component"] == "etcd" && p.Status.Phase == corev1.PodRunning {
			found = true
			out, errOut, err := c.ExecInPod(ctx, p.Namespace, p.Name, "etcd", []string{"etcdctl", "version"})
			if err != nil {
				fmt.Fprintf(w, "  %s: ERROR %v %s\n", p.Name, strutil.FirstLine(err.Error()), strutil.FirstLine(errOut))
			} else {
				fmt.Fprintf(w, "  %s: ok (%s)\n", p.Name, strutil.FirstLine(out))
			}
			if diagEtcd != nil {
				diagEtcd(ctx, c, p.Spec.NodeName, p.Name, w)
			}
			break
		}
	}
	if !found {
		fmt.Fprintln(w, "  no running etcd pod with label component=etcd in kube-system")
	}

	fmt.Fprintln(w, "\n== other lists ==")
	for _, r := range []struct {
		name string
		f    func() error
	}{
		{"secrets (helm releases)", func() error {
			_, err := c.CS.CoreV1().Secrets("").List(ctx, metav1.ListOptions{FieldSelector: "type=helm.sh/release.v1", Limit: 1})
			return err
		}},
		{"events", func() error {
			_, err := c.CS.CoreV1().Events("").List(ctx, metav1.ListOptions{Limit: 1})
			return err
		}},
		{"clusterrolebindings", func() error {
			_, err := c.CS.RbacV1().ClusterRoleBindings().List(ctx, metav1.ListOptions{Limit: 1})
			return err
		}},
		{"customresourcedefinitions", func() error {
			_, err := c.Dyn.Resource(crdGVR).List(ctx, metav1.ListOptions{Limit: 1})
			return err
		}},
		{"readyz", func() error { _, err := c.healthz(ctx, "/readyz"); return err }},
	} {
		if err := r.f(); err != nil {
			fmt.Fprintf(w, "  %-28s ERROR %v\n", r.name, strutil.FirstLine(err.Error()))
		} else {
			fmt.Fprintf(w, "  %-28s ok\n", r.name)
		}
	}
}

// diagEtcd is set by the etcd package consumer (main) to avoid an import cycle.
var diagEtcd func(ctx context.Context, c *Client, node, pod string, w io.Writer)

// SetEtcdDiag registers the etcd probe used by Diag.
func SetEtcdDiag(f func(ctx context.Context, c *Client, node, pod string, w io.Writer)) { diagEtcd = f }

// pvSource names the volume source of a PV and its host path when local.
func pvSource(pv *corev1.PersistentVolume) (string, string) {
	src := pv.Spec.PersistentVolumeSource
	switch {
	case src.CSI != nil:
		return "csi:" + src.CSI.Driver, ""
	case src.HostPath != nil:
		return "hostPath", src.HostPath.Path
	case src.Local != nil:
		return "local", src.Local.Path
	case src.NFS != nil:
		return "nfs", src.NFS.Server + ":" + src.NFS.Path
	case src.ISCSI != nil:
		return "iscsi", ""
	case src.RBD != nil:
		return "rbd", ""
	case src.CephFS != nil:
		return "cephfs", ""
	}
	return "other", ""
}
