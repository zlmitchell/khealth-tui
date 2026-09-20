package ui

import (
	"fmt"
	"testing"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"

	"k8s-health-tui/internal/logs"
	"k8s-health-tui/internal/stig"
)

// logsLinesApp is a Logs-lines view over a realistic journal: 3 units x
// 400 lines of mixed klog / logfmt / JSON, as a busy node returns.
func logsLinesApp() *App {
	a := testApp()
	a.height, a.width = 50, 200
	var lines []string
	for i := 0; i < 1200; i++ {
		var l string
		switch i % 3 {
		case 0:
			l = fmt.Sprintf("2024-09-18T10:%02d:00+00:00 cp-1 rke2[1]: time=\"2024-09-18T10:%02d:00Z\" level=error msg=\"Failed to connect to proxy. Empty dialer response\" error=\"dial tcp 10.0.0.%d:9345: connect: connection refused\"", i%60, i%60, i%250)
		case 1:
			l = fmt.Sprintf("2024-09-18T10:%02d:00+00:00 cp-1 kubelet[1234]: E0918 10:%02d:00.123456    1234 kubelet.go:2855] \"Container runtime network not ready\" networkReady=\"NetworkReady=false reason:NetworkPluginNotReady message:Network plugin returns error: cni plugin not initialized\" iteration=%d", i%60, i%60, i)
		default:
			l = fmt.Sprintf("2024-09-18T10:%02d:00+00:00 cp-1 containerd[999]: {\"level\":\"warn\",\"ts\":\"2024-09-18T10:%02d:00.000Z\",\"caller\":\"v3rpc/interceptor.go:197\",\"msg\":\"request stats\",\"detail\":\"key:\\\"/registry/leases/kube-node-lease/cp-1\\\" \",\"duration\":\"%dms\"}", i%60, i%60, i)
		}
		lines = append(lines, l)
	}
	a.nodes["cp-1"].Journal = lines
	a.logSum["cp-1"] = logs.Classify(lines, a.lastRefresh)
	a.logsAll = true
	a.tab = tabLogs
	a.handleKey(tea.KeyMsg{Type: tea.KeyEnter})
	return a
}

// BenchmarkLogsLinesSpinnerTick is what one spinner tick (12 per second)
// costs on the Logs lines view: the Update plus the View it triggers.
func BenchmarkLogsLinesSpinnerTick(b *testing.B) {
	a := logsLinesApp()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		a.Update(spinner.TickMsg{})
		a.View()
	}
}

// BenchmarkLogsLinesCursorDown is one j/k press and the frame after it.
func BenchmarkLogsLinesCursorDown(b *testing.B) {
	a := logsLinesApp()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		a.Update(tea.KeyMsg{Type: tea.KeyDown})
		a.View()
	}
}

// securityApp is a scanned Security tab with a RHEL-sized OS STIG result
// set: ~450 rules, each with a three-node detail, plus the cluster rules.
func securityApp() *App {
	a := testApp()
	a.height, a.width = 50, 200
	a.secScanned = true
	a.recompute()
	for i := 0; i < 450; i++ {
		st := stig.Pass
		switch i % 9 {
		case 0:
			st = stig.Fail
		case 1:
			st = stig.Manual
		case 2:
			st = stig.NA
		}
		detail := ""
		if st != stig.Pass {
			detail = fmt.Sprintf("redhat9-test: /etc/ssh/sshd_config.d/ mode 700 (want 0600 or stricter) rule %d; redhat9-test-2: /etc/ssh/sshd_config.d/ mode 700 (want 0600 or stricter); redhat9-test-3: /etc/ssh/sshd_config.d/ mode 700 (want 0600 or stricter)", i)
		} else {
			detail = "3/3 nodes"
		}
		a.stigRes = append(a.stigRes, stig.Result{ID: fmt.Sprintf("V-2578%02d", i), RuleID: fmt.Sprintf("RHEL-09-%06d", i), Title: fmt.Sprintf("RHEL 9 must do the thing number %d so that the other thing stays configured", i), Cat: "II", Group: "os", Status: st, Detail: detail, Ref: "DISA RHEL 9 STIG V2R9", Fix: "fix it", Check: "check it",
			PerNode: map[string]stig.Status{"redhat9-test": st, "redhat9-test-2": st, "redhat9-test-3": st}})
	}
	a.tab = tabSecurity
	return a
}

// BenchmarkSecuritySubTabSwitch is one l/h press on the Security tab and
// the frame after it, cycling through the three sub-tabs.
func BenchmarkSecuritySubTabSwitch(b *testing.B) {
	a := securityApp()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		a.Update(tea.KeyMsg{Type: tea.KeyRight})
		a.View()
	}
}

// BenchmarkSecurityOSStigBuild is the OS STIG sub-tab content alone.
func BenchmarkSecurityOSStigBuild(b *testing.B) {
	a := securityApp()
	a.sub[tabSecurity] = 2
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		a.buildContent()
	}
}

// BenchmarkRecompute is the local work every snapshot and every coalesced
// node/etcd/helm message burst triggers: log classification of every
// node's journal, the STIG evaluation and the checks.
func BenchmarkRecompute(b *testing.B) {
	a := logsLinesApp()
	a.secScanned = true
	for _, n := range []string{"cp-2", "cp-3"} {
		ni := *a.nodes["cp-1"]
		ni.Node = n
		a.nodes[n] = &ni
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		a.recompute()
	}
}

// BenchmarkTabBuilds is the cost of building every tab and sub-tab from
// the rich test cluster: a builder must render state, not derive it, so
// every one of these should be low single-digit milliseconds.
func BenchmarkTabBuilds(b *testing.B) {
	a := newDriveApp(b)
	a.Update(tea.WindowSizeMsg{Width: 200, Height: 50})
	a.secScanned = true
	a.recompute()
	for t := tab(0); t < tabCount; t++ {
		subs := subTabs[t]
		if len(subs) == 0 {
			subs = []string{""}
		}
		for si, sub := range subs {
			a.tab, a.sub[t] = t, si
			if t == tabLogs && sub == "Lines" {
				a.logsNode = "cp-1"
			} else {
				a.logsNode = ""
			}
			b.Run(fmt.Sprintf("%s/%s", a.tabName(t), sub), func(b *testing.B) {
				for i := 0; i < b.N; i++ {
					a.buildContent()
				}
			})
		}
	}
}
