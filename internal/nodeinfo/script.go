// Package nodeinfo collects host-level facts from cluster nodes over SSH:
// resources, disks, services, certificates, security settings, registries,
// images and (in heavy mode) journal logs.
package nodeinfo

import (
	_ "embed"
	"fmt"
	"regexp"
	"strings"

	"k8s-health-tui/internal/perf"
	"k8s-health-tui/internal/stigdata"
)

// Options controls what the node script collects.
type Options struct {
	Heavy         bool     // include images, tarball manifests and journal
	Config        bool     // include the config tier of the base script: certs, sysctls, file modes, slow hardening commands, rke2/k3s config, manifests, registries (heavy cycles / first contact / R; carried forward otherwise by Info.MergeConfig)
	OSStig        bool     // include the OS STIG facts (sysctl -a, packages, units, mounts, sshd -T, audit rules, stat/find scans, config dumps)
	LogLines      int      // journalctl -n
	LogSince      string   // journalctl --since
	KnownTarballs []string // "path|size|mtime" entries whose manifests are already known
	PVPaths       []string // hostPath/local PV directories to measure with du (heavy)
}

var safeSince = regexp.MustCompile(`^[-+0-9a-zA-Z: ]{1,40}$`)
var safePath = regexp.MustCompile(`^/[A-Za-z0-9_./@:+-]{1,400}$`)

// Script returns the POSIX sh script executed on each node.
func Script(o Options) string {
	since := o.LogSince
	if !safeSince.MatchString(since) {
		since = "-24h"
	}
	lines := o.LogLines
	if lines <= 0 || lines > 5000 {
		lines = 400
	}
	known := strings.Join(o.KnownTarballs, "|")
	known = strings.ReplaceAll(known, "'", "")
	var paths []string
	for _, pp := range o.PVPaths {
		if safePath.MatchString(pp) {
			paths = append(paths, pp)
		}
	}

	var b strings.Builder
	b.WriteString(strings.ReplaceAll(baseScript, "__CONFIG__", map[bool]string{true: "1", false: "0"}[o.Config]))
	if o.OSStig {
		b.WriteString(osStigScript)
		b.WriteString(stigdata.ProbeScript())
	}
	if o.Heavy {
		h := strings.ReplaceAll(heavyScript, "__LINES__", fmt.Sprint(lines))
		h = strings.ReplaceAll(h, "__SINCE__", since)
		h = strings.ReplaceAll(h, "__KNOWN__", known)
		h = strings.ReplaceAll(h, "__PVPATHS__", strings.Join(paths, " "))
		b.WriteString(h)
	}
	b.WriteString(perf.Footer)
	b.WriteString("echo '===END'\n")
	return b.String()
}

//go:embed scripts/base.sh
var baseScript string

// osStigScript collects the generic facts the OS STIG templates evaluate
// (see internal/stigdata); the data-derived stat/find/dump sections are
// appended by stigdata.ProbeScript.
//
//go:embed scripts/os_stig.sh
var osStigScript string

//go:embed scripts/heavy.sh
var heavyScript string
