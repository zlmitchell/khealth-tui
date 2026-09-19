package etcd

import (
	"context"
	"strings"
	"testing"
)

func TestEncryptionParse(t *testing.T) {
	out := "===ENCCONFIG\nfile=/etc/kubernetes/enc/enc.yaml\ntokens=secrets configmaps aescbc identity\n" +
		"===ETCDCTL\nvia=host /usr/bin/etcdctl\n---MEMBERS\n[]\n---STATUS\n[]\n---ALARMS\n[]\n---ENCSAMPLE\nkey=/registry/secrets/kube-system/bootstrap-token-abc\nprefix=k8s:enc:aescbc:v1:key1:.....\n===END\n"
	p := Parse("cp-1", out)
	e := p.Encryption
	if e == nil || e.ConfigFile != "/etc/kubernetes/enc/enc.yaml" || strings.Join(e.Providers(), ",") != "aescbc,identity" {
		t.Fatalf("config: %+v", e)
	}
	sampled, enc, prov := e.Sampled()
	if !sampled || !enc || prov != "aescbc" || e.SampleKey != "/registry/secrets/kube-system/bootstrap-token-abc" {
		t.Errorf("sample: %v %v %q %+v", sampled, enc, prov, e)
	}

	// plaintext sample, identity first
	out = "===ENCCONFIG\nfile=/x\ntokens=secrets identity aescbc\n===ETCDCTL\nvia=host x\n---ENCSAMPLE\nkey=/registry/secrets/default/db\nprefix=k8s..v1..Secret..\n===END\n"
	p = Parse("cp-1", out)
	if s, enc, _ := p.Encryption.Sampled(); !s || enc || p.Encryption.Providers()[0] != "identity" {
		t.Errorf("plaintext: %+v", p.Encryption)
	}

	// no encryption config at all
	p = Parse("cp-1", "===ETCDCTL\nvia=host x\n---MEMBERS\n[]\n===END\n")
	if p.Encryption != nil {
		t.Errorf("no config: %+v", p.Encryption)
	}
	if s, _, _ := (*Encryption)(nil).Sampled(); s {
		t.Errorf("nil receiver")
	}

	// carry the sample forward when the etcdctl section was skipped
	prev := Parse("cp-1", "===ETCDCTL\nvia=host x\n---ENCSAMPLE\nkey=/registry/secrets/a/b\nprefix=k8s:enc:kms:v2:p:...\n===END\n")
	next := Parse("cp-1", "===ENCCONFIG\nfile=/x\ntokens=secrets kms\n===ETCDCTL\nskipped=api\n===END\n")
	next.Merge(prev)
	if s, enc, prov := next.Encryption.Sampled(); !s || !enc || prov != "kms" || next.Encryption.ConfigFile != "/x" {
		t.Errorf("merge: %+v", next.Encryption)
	}
}

type fakeExec struct{ vals map[string]string }

func (f fakeExec) ExecInPod(_ context.Context, _, _, _ string, cmd []string) (string, string, error) {
	// cmd = etcdctl --cacert.. --cert.. --key.. [--endpoints=..] <verb> ...
	var args []string
	for _, c := range cmd[1:] {
		if !strings.HasPrefix(c, "--") {
			args = append(args, c)
		}
	}
	if len(args) == 0 {
		return "", "", nil
	}
	switch {
	case args[0] == "member" && args[1] == "list":
		return `{"members":[{"ID":1,"name":"a","peerURLs":["https://10.0.0.1:2380"],"clientURLs":["https://10.0.0.1:2379"]}]}`, "", nil
	case args[0] == "endpoint":
		return "[]", "", nil
	case args[0] == "alarm":
		return "{}", "", nil
	case args[0] == "get" && args[1] == "/registry/secrets/":
		return "/registry/secrets/kube-system/tok\n", "", nil
	case args[0] == "get":
		return f.vals[args[1]], "", nil
	}
	return "", "", nil
}

func TestExecProbeEncryptionSample(t *testing.T) {
	p := ExecProbe(context.Background(), fakeExec{vals: map[string]string{"/registry/secrets/kube-system/tok": "k8s:enc:aescbc:v1:key1:\x00\x01\x02ciphertext"}}, "cp-1", "etcd-cp-1", "kubeadm")
	if s, enc, prov := p.Encryption.Sampled(); !s || !enc || prov != "aescbc" || strings.ContainsAny(p.Encryption.SamplePrefix, "\x00\x01") || len(p.Encryption.SamplePrefix) != 24 {
		t.Errorf("exec sample: %v %v %q %+v", s, enc, prov, p.Encryption)
	}
	p = ExecProbe(context.Background(), fakeExec{vals: map[string]string{"/registry/secrets/kube-system/tok": "k8s\x00\n\x0c\n\x02v1\x12\x06Secret\x12plain"}}, "cp-1", "etcd-cp-1", "kubeadm")
	if s, enc, _ := p.Encryption.Sampled(); !s || enc {
		t.Errorf("exec plaintext: %+v", p.Encryption)
	}
}
