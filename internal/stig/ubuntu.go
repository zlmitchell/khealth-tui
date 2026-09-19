package stig

// DISA Canonical Ubuntu LTS STIG rule tables. Source XCCDF:
//   dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_CAN_Ubuntu_20-04_LTS_V2R4_STIG.zip (Release 4, 01 Oct 2025)
//   dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_CAN_Ubuntu_22-04_LTS_V2R9_STIG.zip (Release 9, 01 Jul 2026)
//   dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_CAN_Ubuntu_24-04_LTS_V1R6_STIG.zip (Release 6, 01 Jul 2026)
// The Ubuntu STIGs carry no fapolicyd/USBGuard/ptrace/core-dump/redirect
// sysctl rules, so those checks are skipped for Ubuntu nodes.

var ubuntuBenchmarks = []OSBenchmark{
	{Name: "DISA Ubuntu 20.04 LTS STIG", Version: "V2R4 (01 Oct 2025)", product: "ubuntu2004", family: "ubuntu", release: "20.04", rules: map[string]osRef{
		"fips":     {"V-238363", "I"},   // NIST FIPS-validated cryptography (fips_enabled)
		"mac":      {"V-238360", "II"},  // AppArmor active and enabled
		"auditd":   {"V-238298", "II"},  // auditd installed, enabled, active
		"firewall": {"V-238355", "II"},  // ufw enabled and running
		"timesync": {"V-238357", "III"}, // chrony against authoritative source
		"aslr":     {"V-238369", "II"},
		"dmesg":    {"V-255913", "III"},
	}},
	{Name: "DISA Ubuntu 22.04 LTS STIG", Version: "V2R9 (01 Jul 2026)", product: "ubuntu2204", family: "ubuntu", release: "22.04", rules: map[string]osRef{
		"fips":     {"V-260650", "I"},
		"mac":      {"V-260557", "II"},
		"auditd":   {"V-260591", "II"},
		"firewall": {"V-260515", "II"},
		"timesync": {"V-260520", "III"},
		"aslr":     {"V-260474", "II"},
		"dmesg":    {"V-260472", "III"},
	}},
	{Name: "DISA Ubuntu 24.04 LTS STIG", Version: "V1R6 (01 Jul 2026)", product: "ubuntu2404", family: "ubuntu", release: "24.04", rules: map[string]osRef{
		"fips":     {"V-270744", "I"},
		"mac":      {"V-270660", "II"},
		"auditd":   {"V-270657", "II"},
		"firewall": {"V-270655", "II"},
		"timesync": {"V-270752", "III"},
		"aslr":     {"V-270772", "II"},
		"dmesg":    {"V-270749", "III"},
	}},
}
