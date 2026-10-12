package nodeinfo

import (
	"strconv"
	"strings"
	"time"
)

// Node-health facts that need a delta between two samples (disk busy time,
// NIC error counters) or that come from the runtime and the CNI's IPAM.

// DiskStat is one whole device's /proc/diskstats counters.
type DiskStat struct {
	Name                           string
	Reads, ReadMs, Writes, WriteMs int64
	BusyMs                         int64 // io_ticks: ms the device had I/O in flight
}

// DiskBusy is a device's utilization over the window between two samples.
type DiskBusy struct {
	Name    string  // dm devices by their device-mapper name (rhel-var)
	UtilPct float64 // share of the window with I/O in flight
	AwaitMs float64 // average time per I/O
	IOPS    float64
}

// BondSlave is one slave of a Linux bond and its MII status.
type BondSlave struct{ Bond, Slave, Status string }

// AVCDeny is an aggregated SELinux denial: who (comm, source type) was
// denied what (target type, class), how often today and when last.
type AVCDeny struct {
	Count              int
	Last               time.Time
	Comm, SType, TType string
	Class              string
}

func parseDisk(sec string) (up float64, stats []DiskStat, dm map[string]string) {
	dm = map[string]string{}
	for i, l := range nonEmpty(sec) {
		f := strings.Fields(l)
		switch {
		case i == 0 && len(f) == 1:
			up, _ = strconv.ParseFloat(f[0], 64)
		case len(f) == 3 && f[0] == "dmname":
			dm[f[1]] = f[2]
		case len(f) == 6:
			n := func(s string) int64 { v, _ := strconv.ParseInt(s, 10, 64); return v }
			stats = append(stats, DiskStat{Name: f[0], Reads: n(f[1]), ReadMs: n(f[2]), Writes: n(f[3]), WriteMs: n(f[4]), BusyMs: n(f[5])})
		}
	}
	return
}

// parseNodeHealth reads the DISK*, NIC, IPAM and RUNTIME sections.
func parseNodeHealth(info *Info, secs map[string]string) {
	var dm map[string]string
	info.DiskUp, info.Disk, dm = parseDisk(secs["DISK1"])
	info.DMNames = dm
	if s, ok := secs["DISK2"]; ok {
		up2, d2, _ := parseDisk(s)
		info.DiskBusy = diskDelta(info.DiskUp, info.Disk, up2, d2, dm)
	}
	info.NIC = map[string]int64{}
	for _, l := range nonEmpty(secs["NIC"]) {
		k, v, _ := strings.Cut(l, "=")
		switch k {
		case "dev":
			info.NICDev = v
		case "bondslave":
			if f := strings.Split(v, "|"); len(f) == 3 {
				info.BondSlaves = append(info.BondSlaves, BondSlave{Bond: f[0], Slave: f[1], Status: f[2]})
			}
		case "neigh":
			info.Neigh, _ = strconv.Atoi(v)
		case "gc_thresh3":
			info.GCThresh3, _ = strconv.Atoi(v)
		default:
			if n, err := strconv.ParseInt(v, 10, 64); err == nil {
				info.NIC[k] = n
			}
		}
	}
	if s, ok := secs["IPAM"]; ok {
		info.IPAMFiles = map[string]int{}
		for _, l := range nonEmpty(s) {
			if net, n, ok := strings.Cut(l, "|"); ok {
				info.IPAMFiles[net], _ = strconv.Atoi(n)
			}
		}
	}
	if s, ok := secs["RUNTIME"]; ok {
		info.RuntimeProbed, info.RuntimeRC, info.NotReadySandboxes = true, -1, -1
		for _, f := range strings.Fields(s) {
			k, v, _ := strings.Cut(f, "=")
			n, _ := strconv.Atoi(v)
			switch k {
			case "rc":
				info.RuntimeRC = n
			case "ms":
				info.RuntimeMs = n
			case "notready":
				info.NotReadySandboxes = n
			}
		}
	}
}

func diskDelta(up1 float64, d1 []DiskStat, up2 float64, d2 []DiskStat, dm map[string]string) []DiskBusy {
	win := up2 - up1
	if win <= 0 {
		return nil
	}
	prev := map[string]DiskStat{}
	for _, d := range d1 {
		prev[d.Name] = d
	}
	var out []DiskBusy
	for _, d := range d2 {
		p, ok := prev[d.Name]
		if !ok || d.BusyMs < p.BusyMs {
			continue // new device or counter reset
		}
		ios := float64(d.Reads - p.Reads + d.Writes - p.Writes)
		b := DiskBusy{Name: d.Name, UtilPct: float64(d.BusyMs-p.BusyMs) / (win * 10), IOPS: ios / win}
		if b.UtilPct > 100 {
			b.UtilPct = 100
		}
		if ios > 0 {
			b.AwaitMs = float64(d.ReadMs-p.ReadMs+d.WriteMs-p.WriteMs) / ios
		}
		if n := dm[d.Name]; n != "" {
			b.Name = n
		}
		out = append(out, b)
	}
	return out
}

// DeltasFromPrev fills the window-based facts from the previous probe of
// the same node: disk utilization and the NIC counters' growth.
func (i *Info) DeltasFromPrev(prev *Info) {
	if prev == nil || prev.Err != nil || i.Err != nil {
		return
	}
	if len(i.DiskBusy) == 0 && len(prev.Disk) > 0 && len(i.Disk) > 0 {
		i.DiskBusy = diskDelta(prev.DiskUp, prev.Disk, i.DiskUp, i.Disk, i.DMNames)
	}
	if i.NICDev != "" && i.NICDev == prev.NICDev {
		i.NICGrowth = map[string]int64{}
		for k, v := range i.NIC {
			if pv, ok := prev.NIC[k]; ok && v > pv {
				i.NICGrowth[k] = v - pv
			}
		}
	}
}
