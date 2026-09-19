//go:build windows

package sshrun

import (
	"time"

	"github.com/Microsoft/go-winio"
	"golang.org/x/crypto/ssh/agent"
)

// dialAgent connects to the Windows OpenSSH agent named pipe.
func dialAgent() (agent.ExtendedAgent, error) {
	timeout := 2 * time.Second
	conn, err := winio.DialPipe(`\.\pipe\openssh-ssh-agent`, &timeout)
	if err != nil {
		return nil, err
	}
	return agent.NewClient(conn), nil
}
