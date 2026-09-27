package nodeinfo

import (
	"path"
	"strings"
	"time"

	"github.com/zlmitchell/khealth-tui/internal/logs"
)

// ClassifyLogs runs the probe's journal and log files through the log
// knowledge base, or returns nil when the probe carried none (a light
// cycle: the caller keeps the previous summary). now is when the lines
// were collected, which decides what counts as recent.
func (i *Info) ClassifyLogs(now time.Time) *logs.Summary {
	if i == nil || (len(i.Journal) == 0 && len(i.LogFiles) == 0) {
		return nil
	}
	// rke2's kubelet/containerd log to files rather than the journal
	srcs := []logs.Source{{Lines: i.Journal}}
	for _, lf := range i.LogFiles {
		srcs = append(srcs, logs.Source{Unit: LogFileUnit(lf.Path), Lines: strings.Split(lf.Content, "\n")})
	}
	return logs.ClassifySources(srcs, now)
}

// LogFileUnit names the unit a log file belongs to: kubelet.log -> kubelet.
func LogFileUnit(p string) string { return strings.TrimSuffix(path.Base(p), ".log") }
