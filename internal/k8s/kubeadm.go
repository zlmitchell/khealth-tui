package k8s

import (
	"context"

	"sigs.k8s.io/yaml"
)

// KubeadmConfig is the part of kubeadm's ClusterConfiguration
// (kube-system/kubeadm-config) that plays the role rke2's config.yaml plays:
// the API endpoint and the extra SANs the apiserver certificate must carry.
// Editing it does not reissue the certificate; `kubeadm certs renew
// apiserver` on each control-plane node does, followed by an apiserver
// restart.
type KubeadmConfig struct {
	ClusterName          string
	ControlPlaneEndpoint string   // host[:port] of the VIP / LB, if set at init
	CertSANs             []string // apiServer.certSANs
	ServiceSubnet        string
	KubernetesVersion    string
	Raw                  string // the ClusterConfiguration document as stored
	KubeletRaw           string // kube-system/kubelet-config KubeletConfiguration (cluster-wide kubelet defaults)
}

// kubeadmConfig reads kube-system/kubeadm-config; nil when absent. The
// error is returned so Fetch can remember a 403/404 (rke2, k3s, managed
// clusters have no kubeadm-config) instead of asking every cycle.
func (c *Client) kubeadmConfig(ctx context.Context) (*KubeadmConfig, error) {
	cm, err := c.CS.CoreV1().ConfigMaps("kube-system").Get(ctx, "kubeadm-config", c.getOpts())
	if err != nil {
		return nil, err
	}
	raw, ok := cm.Data["ClusterConfiguration"]
	if !ok {
		return nil, nil
	}
	var cc struct {
		ClusterName          string `json:"clusterName"`
		ControlPlaneEndpoint string `json:"controlPlaneEndpoint"`
		KubernetesVersion    string `json:"kubernetesVersion"`
		APIServer            struct {
			CertSANs []string `json:"certSANs"`
		} `json:"apiServer"`
		Networking struct {
			ServiceSubnet string `json:"serviceSubnet"`
		} `json:"networking"`
	}
	if err := yaml.Unmarshal([]byte(raw), &cc); err != nil {
		return nil, nil
	}
	kc := &KubeadmConfig{ClusterName: cc.ClusterName, ControlPlaneEndpoint: cc.ControlPlaneEndpoint, CertSANs: cc.APIServer.CertSANs, ServiceSubnet: cc.Networking.ServiceSubnet, KubernetesVersion: cc.KubernetesVersion, Raw: raw}
	if kl, err := c.CS.CoreV1().ConfigMaps("kube-system").Get(ctx, "kubelet-config", c.getOpts()); err == nil {
		kc.KubeletRaw = kl.Data["kubelet"]
	}
	return kc, nil
}
