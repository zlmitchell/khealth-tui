package ui

import (
	"fmt"
	"testing"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"

	"k8s-health-tui/internal/logs"
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
