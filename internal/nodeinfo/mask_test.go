package nodeinfo

import (
	"os/exec"
	"runtime"
	"strings"
	"testing"
)

// server/manifests is where operators keep Secrets and chart values; the
// probe prints those files (RKE2 tab), so every credential form must be
// masked on the node: a Secret's data in block and flow style, env values
// with a credential-looking name in block and flow style, and credential
// keys inside flow mappings. The gatherlab found the flow forms leaking.
func TestMaskManifest(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("needs a POSIX sh")
	}
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no sh")
	}
	manifest := `apiVersion: v1
kind: Secret
metadata: {name: db, namespace: shop}
stringData: {password: leak-flow-secret}
---
apiVersion: v1
kind: Secret
metadata:
  name: s3
data:
  accessKey: bGVhay1ibG9jay1zZWNyZXQ=
  bucket: bGVhay1idWNrZXQ=
type: Opaque
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: web}
spec:
  template:
    spec:
      containers:
      - name: web
        env:
        - {name: DB_PASSWORD, value: leak-flow-env}
        - name: API_TOKEN
          value: leak-block-env
        - {name: LOG_LEVEL, value: debug}
        - name: MODE
          value: keep-this
---
apiVersion: helm.cattle.io/v1
kind: HelmChartConfig
metadata: {name: traefik}
spec:
  valuesContent: |-
    auth: {password: leak-values}
    replicas: 2
`
	cmd := exec.Command("sh", "-c", Prelude()+"\nmaskmanifest /dev/stdin")
	cmd.Stdin = strings.NewReader(manifest)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("sh: %v\n%s", err, out)
	}
	got := string(out)
	for _, leak := range []string{"leak-flow-secret", "bGVhay1ibG9jay1zZWNyZXQ", "bGVhay1idWNrZXQ", "leak-flow-env", "leak-block-env", "leak-values"} {
		if strings.Contains(got, leak) {
			t.Errorf("%s leaks:\n%s", leak, got)
		}
	}
	for _, keep := range []string{"kind: Secret", "name: db", "accessKey: <masked>", "value: debug", "value: keep-this", "replicas: 2", "type: Opaque"} {
		if !strings.Contains(got, keep) {
			t.Errorf("%q lost:\n%s", keep, got)
		}
	}
}

// The kubelet logs a container's whole spec when it cannot start it, env
// values included; scrublog masks every one of them.
func TestScrubLog(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("needs a POSIX sh")
	}
	line := `2026-09-26T23:31:14+0000 lab-node k3s[62]: E0926 kuberuntime_manager.go:1358] "Unhandled Error" err="container &Container{Name:web,Image:busybox:1.36,Env:[]EnvVar{EnvVar{Name:DB_PASSWORD,Value:leak-one,ValueFrom:nil,},EnvVar{Name:DSN,Value:postgres://u:leak,two@db:5432/x,ValueFrom:nil,},EnvVar{Name:LOG_LEVEL,Value:debug,ValueFrom:nil,},},Resources:{}}"`
	cmd := exec.Command("sh", "-c", Prelude()+"\nscrublog")
	cmd.Stdin = strings.NewReader(line + "\n")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("sh: %v\n%s", err, out)
	}
	got := string(out)
	if strings.Contains(got, "leak") || strings.Contains(got, "debug") {
		t.Errorf("env values survive:\n%s", got)
	}
	if strings.Count(got, "Value:<masked>,ValueFrom:") != 3 || !strings.Contains(got, "Name:DB_PASSWORD") || !strings.Contains(got, "Unhandled Error") {
		t.Errorf("scrubbed too much or too little:\n%s", got)
	}
}
