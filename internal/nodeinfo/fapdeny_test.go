package nodeinfo

import (
	"os/exec"
	"strings"
	"testing"
)

// The FAPDENY awk program must read audit records with and without the
// "node=<host> " prefix auditd adds when name_format is set (the STIG sets
// it): anchored record types found nothing on every hardened node.
func TestFapDenyAwkNodePrefix(t *testing.T) {
	sec := preflightScript[strings.Index(preflightScript, "sec FAPDENY"):]
	i := strings.Index(sec, "--input-logs </dev/null 2>/dev/null | awk '")
	if i < 0 {
		t.Fatal("FAPDENY ausearch | awk not found in preflight.sh")
	}
	prog := sec[i+len("--input-logs </dev/null 2>/dev/null | awk '"):]
	prog = prog[:strings.Index(prog, "' | sort")]
	records := map[string]string{
		"plain": `type=FANOTIFY msg=audit(1791749625.433:4309): resp=2 fan_type=1 fan_info=29 subj_trust=2 obj_trust=0
type=SYSCALL msg=audit(1791749625.433:4309): arch=c000003e syscall=59 success=no exit=-1 comm="runuser" exe="/usr/sbin/runuser"
type=PATH msg=audit(1791749625.433:4309): item=0 name="/opt/khtest-runc" inode=6553630
`,
		"name_format": `node=redhat9-test-2 type=FANOTIFY msg=audit(1791749625.433:4309): resp=2 fan_type=1 fan_info=29 subj_trust=2 obj_trust=0
node=redhat9-test-2 type=SYSCALL msg=audit(1791749625.433:4309): arch=c000003e syscall=59 success=no exit=-1 comm="runuser" exe="/usr/sbin/runuser"
node=redhat9-test-2 type=PATH msg=audit(1791749625.433:4309): item=0 name="/opt/khtest-runc" inode=6553630
`,
	}
	for name, in := range records {
		cmd := exec.Command("awk", prog)
		cmd.Stdin = strings.NewReader(in)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("%s: awk: %v\n%s", name, err, out)
		}
		if got := strings.TrimSpace(string(out)); got != "1|1791749625|/usr/sbin/runuser|/opt/khtest-runc" {
			t.Errorf("%s: got %q", name, got)
		}
	}
}

// The AVC aggregation: types after a blank (name_format), contexts reduced
// to their type, one line per comm/source/target/class.
func TestAVCDenyAwk(t *testing.T) {
	sec := preflightScript[strings.Index(preflightScript, "sec AVCDENY"):]
	i := strings.Index(sec, "--input-logs </dev/null 2>/dev/null | awk '")
	prog := sec[i+len("--input-logs </dev/null 2>/dev/null | awk '"):]
	prog = prog[:strings.Index(prog, "' | sort")]
	in := `node=n1 type=AVC msg=audit(1791749625.433:4309): avc:  denied  { read } for  pid=42 comm="cat" name="secret" dev="dm-0" ino=1 scontext=system_u:system_r:container_t:s0:c1,c2 tcontext=unconfined_u:object_r:admin_home_t:s0 tclass=file permissive=0
type=AVC msg=audit(1791749630.001:4310): avc:  denied  { read } for  pid=43 comm="cat" name="secret" scontext=system_u:system_r:container_t:s0:c1,c2 tcontext=unconfined_u:object_r:admin_home_t:s0 tclass=file permissive=0
type=AVC msg=audit(1791749631.001:4311): avc:  granted  { setenforce } for pid=1 comm="x" scontext=a:b:c:s0 tcontext=a:b:c:s0 tclass=security
`
	cmd := exec.Command("awk", prog)
	cmd.Stdin = strings.NewReader(in)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("awk: %v\n%s", err, out)
	}
	if got := strings.TrimSpace(string(out)); got != "2|1791749630|cat|container_t|admin_home_t|file" {
		t.Errorf("got %q", got)
	}
}
