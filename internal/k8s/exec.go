package k8s

import (
	"bytes"
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/remotecommand"
)

// ExecInPod runs a command in a container through the API server (pods/exec)
// and returns stdout/stderr. Needs RBAC create on pods/exec.
func (c *Client) ExecInPod(ctx context.Context, ns, pod, container string, cmd []string) (string, string, error) {
	req := c.CS.CoreV1().RESTClient().Post().Resource("pods").Namespace(ns).Name(pod).SubResource("exec")
	req.VersionedParams(&corev1.PodExecOptions{
		Container: container,
		Command:   cmd,
		Stdout:    true,
		Stderr:    true,
	}, scheme.ParameterCodec)
	exec, err := remotecommand.NewSPDYExecutor(c.Config, "POST", req.URL())
	if err != nil {
		return "", "", err
	}
	var stdout, stderr bytes.Buffer
	err = exec.StreamWithContext(ctx, remotecommand.StreamOptions{Stdout: &stdout, Stderr: &stderr})
	if err != nil {
		return stdout.String(), stderr.String(), fmt.Errorf("exec %s/%s: %w", ns, pod, err)
	}
	return stdout.String(), stderr.String(), nil
}

// EtcdPods returns the static etcd pods in kube-system keyed by node name.
func (s *Snapshot) EtcdPods() map[string]*corev1.Pod {
	out := map[string]*corev1.Pod{}
	for i := range s.Pods {
		p := &s.Pods[i]
		if p.Namespace != "kube-system" {
			continue
		}
		if p.Labels["component"] == "etcd" || (len(p.Name) > 5 && p.Name[:5] == "etcd-" && p.Spec.NodeName != "" && p.Name == "etcd-"+p.Spec.NodeName) {
			if p.Status.Phase == corev1.PodRunning {
				out[p.Spec.NodeName] = p
			}
		}
	}
	return out
}
