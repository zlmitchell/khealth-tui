//go:build !windows

package sshrun

import (
	"context"
	"net"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh/agent"

	"github.com/zlmitchell/khealth-tui/internal/sshrun/sshtest"
)

// An ssh-agent holding the client key is enough to log in; a socket that
// does not answer is reported and skipped.
func TestAgentAuth(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	srv := sshtest.New(t, hostHandler{uid: "0"}.handle)
	sock := filepath.Join(t.TempDir(), "agent.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Skip("unix sockets unavailable:", err)
	}
	t.Cleanup(func() { ln.Close() })
	keyring := agent.NewKeyring()
	if err := keyring.Add(agent.AddedKey{PrivateKey: srv.ClientKey}); err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { _ = agent.ServeAgent(keyring, c) }()
		}
	}()
	t.Setenv("SSH_AUTH_SOCK", sock)
	cfg := testCfg(srv)
	cfg.Key = ""
	r, err := New(cfg)
	if err != nil || strings.Join(r.Notes(), ";") != "ssh-agent" {
		t.Fatalf("agent auth: %v %v", err, r.Notes())
	}
	t.Cleanup(r.Close)
	if res := r.Run(context.Background(), srv.Addr, "s\n"); res.Err != nil {
		t.Errorf("run with agent key: %v", res.Err)
	}

	t.Setenv("SSH_AUTH_SOCK", filepath.Join(t.TempDir(), "missing.sock"))
	if _, err := New(cfg); err == nil || !strings.Contains(err.Error(), "agent: dial unix") {
		t.Errorf("dead agent socket: %v", err)
	}
}
