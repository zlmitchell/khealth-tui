package sshrun

import (
	"strings"
	"testing"
)

func TestParseBecomeProbe(t *testing.T) {
	uid, tools := parseBecomeProbe("1000\ntool=dzdo\ntool=sudo\n")
	if uid != "1000" || strings.Join(tools, ",") != "sudo,dzdo" {
		t.Errorf("got uid=%q tools=%v", uid, tools)
	}
	uid, tools = parseBecomeProbe("0\n")
	if uid != "0" || len(tools) != 0 {
		t.Errorf("root: uid=%q tools=%v", uid, tools)
	}
	uid, tools = parseBecomeProbe("  1001  \ntool=doas\n")
	if uid != "1001" || strings.Join(tools, ",") != "doas" {
		t.Errorf("doas only: uid=%q tools=%v", uid, tools)
	}
}

func TestClassifyBecomeFailure(t *testing.T) {
	cases := []struct {
		stderr   string
		needPass bool
		reason   string
	}{
		{"sudo: a password is required\n", true, "password required"},
		{"dzdo: a password is required", true, "password required"},
		{"doas: Authentication failed: password required", true, "password required"},
		{"admin is not in the sudoers file.  This incident will be reported.", false, "not permitted for this user"},
		{"dzdo: admin is not allowed to run dzdo on node1", false, "not permitted for this user"},
		{"doas: Operation not permitted", false, "not permitted for this user"},
		{"sudo: sorry, you must have a tty to run sudo", false, "needs a terminal (requiretty?)"},
		{"something odd happened\nsecond line", false, "something odd happened"},
		{"", false, "sudo did not return uid 0"},
	}
	for _, c := range cases {
		np, reason := classifyBecomeFailure("sudo", c.stderr)
		if np != c.needPass || reason != c.reason {
			t.Errorf("%q: got (%v, %q) want (%v, %q)", c.stderr, np, reason, c.needPass, c.reason)
		}
	}
}

func TestBecomeMethodCommand(t *testing.T) {
	cases := []struct {
		m        becomeMethod
		cmd      string
		needPass bool
		label    string
	}{
		{becomeMethod{}, "/bin/sh -s", false, "root"},
		{becomeMethod{tool: "sudo"}, "sudo -n /bin/sh -s", false, "sudo (NOPASSWD)"},
		{becomeMethod{tool: "dzdo", withPass: true}, "dzdo -S -p '' /bin/sh -s", true, "dzdo (password)"},
		{becomeMethod{tool: "doas"}, "doas -n /bin/sh -s", false, "doas (NOPASSWD)"},
	}
	for _, c := range cases {
		cmd, np := c.m.command()
		if cmd != c.cmd || np != c.needPass || c.m.String() != c.label {
			t.Errorf("%+v: got %q %v %q", c.m, cmd, np, c.m.String())
		}
	}
}
