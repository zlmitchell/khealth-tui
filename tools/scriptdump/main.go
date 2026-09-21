// Command scriptdump prints the SSH node probe script so it can be syntax
// checked or run against a stock OS image (see docs/STIG.md).
package main

import (
	"flag"
	"fmt"

	"github.com/zlmitchell/khealth-tui/internal/nodeinfo"
)

func main() {
	heavy := flag.Bool("heavy", false, "include the heavy (images, journal) sections")
	cfgTier := flag.Bool("config", true, "include the config tier (certs, sysctls, config files, slow hardening commands)")
	stig := flag.Bool("stig", false, "include the OS STIG sections")
	cpuSample := flag.Bool("cpu-sample", false, "sample /proc/stat twice with a 1 s sleep (first contact)")
	flag.Parse()
	fmt.Print(nodeinfo.Script(nodeinfo.Options{Journal: *heavy, Images: *heavy, PVs: *heavy, Config: *cfgTier, OSStig: *stig, CPUSample: *cpuSample}))
}
