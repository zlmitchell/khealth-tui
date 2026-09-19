package k8s

import (
	"context"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

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
			fmt.Fprintf(w, "  configz:       ERROR %v\n", firstLineOf(err.Error()))
		} else {
			fmt.Fprintf(w, "  configz:       ok (%s)\n", time.Since(t).Round(time.Millisecond))
		}
		t = time.Now()
		raw, err := c.CS.CoreV1().RESTClient().Get().Resource("nodes").Name(n.Name).SubResource("proxy").Suffix("stats/summary").Do(ctx).Raw()
		if err != nil {
			fmt.Fprintf(w, "  stats/summary: ERROR %v\n", firstLineOf(err.Error()))
			if len(raw) > 0 {
				fmt.Fprintf(w, "                 body: %s\n", firstLineOf(string(raw)))
			}
			continue
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
			fmt.Fprintf(w, "    %-50s used %s of %s (%.0f%%) pod %s\n", k, human(float64(u.Used)), human(float64(u.Capacity)), u.UsedPct(), u.Pod)
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
				fmt.Fprintf(w, "    raw volume sample: %s\n", firstLineOf(snippet))
			}
		}
	}

	fmt.Fprintln(w, "\n== metrics.k8s.io ==")
	if m, err := c.nodeMetrics(ctx); err != nil {
		fmt.Fprintf(w, "  ERROR %v\n", firstLineOf(err.Error()))
	} else {
		fmt.Fprintf(w, "  ok, %d nodes\n", len(m))
	}

	fmt.Fprintln(w, "\n== pods/exec into etcd static pod ==")
	found := false
	for i := range pods.Items {
		p := &pods.Items[i]
		if p.Namespace == "kube-system" && p.Labels["component"] == "etcd" && p.Status.Phase == corev1.PodRunning {
			found = true
			out, errOut, err := c.ExecInPod(ctx, p.Namespace, p.Name, "etcd", []string{"sh", "-c", "etcdctl version 2>&1 | head -1"})
			if err != nil {
				fmt.Fprintf(w, "  %s: ERROR %v %s\n", p.Name, firstLineOf(err.Error()), firstLineOf(errOut))
			} else {
				fmt.Fprintf(w, "  %s: ok (%s)\n", p.Name, firstLineOf(out))
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
			fmt.Fprintf(w, "  %-28s ERROR %v\n", r.name, firstLineOf(err.Error()))
		} else {
			fmt.Fprintf(w, "  %-28s ok\n", r.name)
		}
	}
}

func firstLineOf(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 300 {
		s = s[:300] + "..."
	}
	return s
}

func human(b float64) string {
	units := []string{"B", "KiB", "MiB", "GiB", "TiB"}
	i := 0
	for b >= 1024 && i < len(units)-1 {
		b /= 1024
		i++
	}
	return fmt.Sprintf("%.1f%s", b, units[i])
}
