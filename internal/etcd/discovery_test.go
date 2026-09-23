package etcd

import (
	"os/exec"
	"runtime"
	"strings"
	"testing"
)

// The probe works out where a host's own backup job writes, so the files
// are scanned and the rescue can offer them. That logic is shell, and the
// patterns it has to survive are real command lines, so it is exercised as
// shell rather than reasoned about.
func TestBackupPathDiscovery(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("needs a POSIX shell")
	}
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no sh")
	}
	fn := extractShellFunc(t, script, "paths_in")

	for _, c := range []struct {
		name, line, want string
	}{
		{
			// what the kubeadm hardening writes: the destination only ever
			// appears as a shell default inside the wrapper script
			name: "shell default",
			line: `BACKUP_DIR=${BACKUP_DIR:-/var/lib/etcd-backup}`,
			want: "/var/lib/etcd-backup",
		},
		{
			name: "etcdctl in a crontab line",
			line: `0 */6 * * * root ETCDCTL_API=3 etcdctl snapshot save /srv/backups/etcd/snap-$(date +%F).db`,
			want: "/srv/backups/etcd", // via the parent of the expanded name
		},
		{
			name: "quoted destination",
			line: `etcdutl snapshot save "/mnt/nfs/etcd/backup.db"`,
			want: "/mnt/nfs/etcd/backup.db",
		},
		{
			name: "plain assignment",
			line: `SNAPSHOT_DIR=/opt/etcd/snaps`,
			want: "/opt/etcd/snaps",
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			out := runShell(t, fn+"\npaths_in \"$1\"\n", c.line)
			found := false
			for _, got := range strings.Fields(out) {
				if got == c.want || strings.HasPrefix(c.want, got+"/") || strings.HasPrefix(got, c.want) {
					found = true
				}
			}
			if !found {
				t.Errorf("no path for %s\nline: %s\ngot:  %q\nwant: %s", c.name, c.line, out, c.want)
			}
		})
	}

	// A credential sitting next to the path must not come out with it: the
	// env file these are read from holds S3 keys.
	out := runShell(t, fn+"\npaths_in \"$1\"\n", `S3_SECRET_KEY=hunter2 S3_ACCESS_KEY=AKIA BACKUP_DIR=/srv/etcd`)
	if strings.Contains(out, "hunter2") || strings.Contains(out, "AKIA") {
		t.Errorf("a secret leaked out of the path extraction: %q", out)
	}
	if !strings.Contains(out, "/srv/etcd") {
		t.Errorf("the directory was not found: %q", out)
	}
}

// extractShellFunc pulls one function definition out of the probe script so
// the test runs the shipped code, not a copy of it.
func extractShellFunc(t *testing.T, src, name string) string {
	t.Helper()
	start := strings.Index(src, "\n"+name+"() {")
	if start < 0 {
		t.Fatalf("%s() is not in the probe script any more", name)
	}
	rest := src[start+1:]
	end := strings.Index(rest, "\n}\n")
	if end < 0 {
		t.Fatalf("%s() has no end", name)
	}
	return rest[:end+3]
}

func runShell(t *testing.T, body, arg string) string {
	t.Helper()
	cmd := exec.Command("sh", "-s", arg)
	cmd.Stdin = strings.NewReader(body)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("sh: %v\n%s", err, out)
	}
	return string(out)
}
