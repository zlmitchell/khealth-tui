package nodeinfo

import (
	"strings"
	"testing"
	"time"
)

// TestNetworkSections: NETLINK (every probe) and NETPROBE (config tier)
// parse into links, the default device, flannel facts and probe results;
// the probe results are carried forward by MergeConfig; the CNI conf's mtu
// is read; the script only carries validated targets.
func TestNetworkSections(t *testing.T) {
	out := "===NETLINK\nlo 65536 UNKNOWN LOOPBACK,UP,LOWER_UP\nenp1s0 1500 UP BROADCAST,MULTICAST,UP,LOWER_UP\nflannel.1 1450 UNKNOWN BROADCAST,MULTICAST,UP,LOWER_UP\ncni0 1450 UP BROADCAST,MULTICAST,UP,LOWER_UP\ndefault=enp1s0\nflannel_mtu=1450\nflannel_network=10.42.0.0/16\n" +
		"===NETPROBE\nPING|cp-2|10.42.2.2|ok|0.730\nPING|cp-3|10.42.1.2|fail|From 10.42.0.1 icmp_seq=1 Destination Host Unreachable\nDNS|10.42.1.2|ok|10.43.0.1\nDNS|10.43.0.10|fail|;; connection timed out; no servers could be reached\nTCP|10.43.0.1:443|ok|0.000937\nPING|cp-4|10.42.3.3|skip|no ping on the node\n" +
		"===CNI\n--- /etc/cni/net.d/10-canal.conflist\n{\"name\":\"k8s-pod-network\",\"cniVersion\":\"0.3.1\",\"plugins\":[{\"type\":\"calico\",\"mtu\":1450,\"ipam\":{\"type\":\"host-local\"}},{\"type\":\"portmap\"}]}\n===END\n"
	info := Parse("cp-1", "h", out, time.Now())
	if len(info.Links) != 4 || info.DefaultDev != "enp1s0" || info.Link("flannel.1") == nil || info.Link("flannel.1").MTU != 1450 || info.Link("enp1s0").State != "UP" {
		t.Fatalf("links: %+v default=%q", info.Links, info.DefaultDev)
	}
	if info.Flannel["mtu"] != "1450" || info.Flannel["network"] != "10.42.0.0/16" {
		t.Errorf("flannel: %v", info.Flannel)
	}
	if !info.NetProbed || len(info.NetProbes) != 6 {
		t.Fatalf("probes: %+v", info.NetProbes)
	}
	p := info.NetProbes
	if p[0].Kind != "PING" || p[0].Node != "cp-2" || !p[0].OK || p[0].Detail != "0.730" || p[1].OK || !strings.Contains(p[1].Detail, "Unreachable") || p[3].Kind != "DNS" || p[3].OK || p[4].Kind != "TCP" || !p[4].OK || !p[5].Skip {
		t.Errorf("probe fields: %+v", p)
	}
	if len(info.CNI) != 1 || info.CNI[0].MTU != 1450 || info.CNI[0].Types[0] != "calico" {
		t.Errorf("cni conf: %+v", info.CNI)
	}
	info.ConfigProbed = true // as a config-tier probe sets it
	light := Parse("cp-1", "h", "===NETLINK\nenp1s0 1500 UP BROADCAST\ndefault=enp1s0\n===END\n", time.Now())
	light.MergeConfig(info)
	if !light.NetProbed || len(light.NetProbes) != 6 || len(light.Links) != 1 {
		t.Errorf("merge: probed=%v probes=%d links=%d", light.NetProbed, len(light.NetProbes), len(light.Links))
	}
	s := Script(Options{Config: true, NetTargets: []string{"cp-2=10.42.2.2", "bad node=1.2.3.4", "cp-3=not-an-ip"}, DNSPods: []string{"10.42.1.2", "x"}, DNSIP: "10.43.0.10", APISvcIP: "10.43.0.1"})
	if !strings.Contains(s, "for t in cp-2=10.42.2.2; do") || !strings.Contains(s, "for d in 10.42.1.2; do") || !strings.Contains(s, "DNSIP=10.43.0.10; APISVC=10.43.0.1") {
		i := strings.Index(s, "sec NETPROBE")
		t.Errorf("script targets not substituted or not filtered:\n%s", s[i:i+400])
	}
	if strings.Contains(Script(Options{}), "__NETTARGETS__") {
		t.Errorf("placeholder left in the light script")
	}
}
