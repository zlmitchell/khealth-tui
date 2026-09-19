//go:build !windows

package sshrun

import (
	"errors"
	"net"
	"os"

	"golang.org/x/crypto/ssh/agent"
)

func dialAgent() (agent.ExtendedAgent, error) {
	sock := os.Getenv("SSH_AUTH_SOCK")
	if sock == "" {
		return nil, errors.New("SSH_AUTH_SOCK not set")
	}
	conn, err := net.Dial("unix", sock)
	if err != nil {
		return nil, err
	}
	return agent.NewClient(conn), nil
}
