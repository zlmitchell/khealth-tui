package stig

// DISA Red Hat Enterprise Linux STIG rule tables. Source XCCDF:
//   dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_RHEL_8_V2R8_STIG.zip  (Release 8, 01 Jul 2026)
//   dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_RHEL_9_V2R9_STIG.zip  (Release 9, 01 Jul 2026)
//   dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_RHEL_10_V1R2_STIG.zip (Release 2, 01 Jul 2026)
// Keys are osCheck.key values from os.go; the category is the STIG severity.

var rhelBenchmarks = []OSBenchmark{
	{Name: "DISA RHEL 8 STIG", Version: "V2R8 (01 Jul 2026)", family: "rhel", release: "8", rules: map[string]osRef{
		"fips":                     {"V-230223", "I"},  // FIPS 140-3 systemwide crypto policy (fips-mode-setup)
		"mac":                      {"V-230240", "II"}, // SELinux enforcing
		"fapolicyd":                {"V-244546", "II"}, // fapolicyd deny-all, permit-by-exception
		"auditd":                   {"V-230411", "II"}, // audit package installed / service running
		"firewall":                 {"V-244544", "II"}, // firewall active
		"usbguard":                 {"V-244548", "II"}, // USBGuard enabled
		"timesync":                 {"V-230484", "II"}, // chrony against authoritative source
		"aslr":                     {"V-230280", "II"},
		"dmesg":                    {"V-230269", "III"},
		"kptr":                     {"V-230547", "II"},
		"ptrace":                   {"V-230546", "II"},
		"core_pattern":             {"V-230311", "II"},
		"protected_symlinks":       {"V-230267", "II"},
		"protected_hardlinks":      {"V-230268", "II"},
		"accept_redirects_all":     {"V-244553", "II"},
		"accept_redirects_default": {"V-244550", "II"},
		"source_route_all":         {"V-244551", "II"},
		"source_route_default":     {"V-244552", "II"},
		"echo_broadcast":           {"V-230537", "II"},
	}},
	{Name: "DISA RHEL 9 STIG", Version: "V2R9 (01 Jul 2026)", family: "rhel", release: "9", rules: map[string]osRef{
		"fips":                     {"V-258230", "I"},
		"mac":                      {"V-258078", "I"},
		"fapolicyd":                {"V-270180", "II"},
		"auditd":                   {"V-258152", "II"},
		"firewall":                 {"V-257936", "II"},
		"usbguard":                 {"V-258036", "II"},
		"timesync":                 {"V-257944", "II"},
		"aslr":                     {"V-257809", "II"},
		"dmesg":                    {"V-257797", "II"},
		"kptr":                     {"V-257800", "II"},
		"ptrace":                   {"V-257811", "II"},
		"core_pattern":             {"V-257803", "II"},
		"protected_symlinks":       {"V-257802", "II"},
		"protected_hardlinks":      {"V-257801", "II"},
		"accept_redirects_all":     {"V-257958", "II"},
		"accept_redirects_default": {"V-257963", "II"},
		"source_route_all":         {"V-257959", "II"},
		"source_route_default":     {"V-257964", "II"},
		"echo_broadcast":           {"V-257966", "II"},
	}},
	{Name: "DISA RHEL 10 STIG", Version: "V1R2 (01 Jul 2026)", family: "rhel", release: "10", rules: map[string]osRef{
		"fips":                     {"V-281009", "I"},
		"mac":                      {"V-281251", "II"},
		"fapolicyd":                {"V-280971", "II"},
		"auditd":                   {"V-280994", "II"},
		"firewall":                 {"V-280956", "II"},
		"usbguard":                 {"V-280963", "II"},
		"timesync":                 {"V-280959", "II"},
		"aslr":                     {"V-281315", "II"},
		"dmesg":                    {"V-281305", "II"},
		"kptr":                     {"V-281308", "II"},
		"ptrace":                   {"V-281316", "II"},
		"core_pattern":             {"V-281311", "II"},
		"protected_symlinks":       {"V-281310", "II"},
		"protected_hardlinks":      {"V-281309", "II"},
		"accept_redirects_all":     {"V-281341", "II"},
		"accept_redirects_default": {"V-281346", "II"},
		"source_route_all":         {"V-281342", "II"},
		"source_route_default":     {"V-281347", "II"},
		"echo_broadcast":           {"V-281349", "II"},
	}},
}
