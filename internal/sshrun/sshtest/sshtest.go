// Package sshtest runs an in-process SSH server for tests. It accepts one
// generated client key (and optionally a password), answers "exec" requests
// through a handler that sees the command and everything sent on stdin, and
// forwards direct-tcpip channels so it can stand in as a bastion.
package sshtest

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// Handler answers one exec request: the remote command, what the client
// wrote on stdin, and what the "process" printed and exited with.
type Handler func(cmd, stdin string) (stdout, stderr string, exit int)

// Server is a running SSH server.
type Server struct {
	Addr      string             // 127.0.0.1:port
	KeyPath   string             // PEM file with the client private key the server accepts
	ClientKey ed25519.PrivateKey // the same key, for ssh-agent tests
	ClientPub ssh.PublicKey
	HostKey   ssh.PublicKey

	// User restricts logins to this name ("" = any); Password, when set, is
	// accepted through both password and keyboard-interactive auth.
	User     string
	Password string
	// Interactive answers keyboard-interactive only (no "password" method).
	Interactive bool

	handler Handler
	ln      net.Listener
	config  *ssh.ServerConfig

	mu       sync.Mutex
	conns    map[*ssh.ServerConn]struct{}
	accepted [][]byte // marshalled public keys that may log in
	execs    int
	dials    int
}

// New starts a server; it is closed when the test ends.
func New(t testing.TB, h Handler) *Server {
	t.Helper()
	hostPub, hostPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hostSigner, err := ssh.NewSignerFromKey(hostPriv)
	if err != nil {
		t.Fatal(err)
	}
	_, clientPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(clientPriv, "sshtest")
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(t.TempDir(), "id_ed25519")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	clientPub, err := ssh.NewPublicKey(clientPriv.Public())
	if err != nil {
		t.Fatal(err)
	}
	hostKey, _ := ssh.NewPublicKey(hostPub)
	s := &Server{KeyPath: keyPath, ClientKey: clientPriv, ClientPub: clientPub, HostKey: hostKey, handler: h, conns: map[*ssh.ServerConn]struct{}{}, accepted: [][]byte{clientPub.Marshal()}}
	s.config = &ssh.ServerConfig{
		PublicKeyCallback: func(c ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
			if !s.userOK(c.User()) || !s.keyOK(k) {
				return nil, errors.New("sshtest: key not accepted")
			}
			return nil, nil
		},
		PasswordCallback: func(c ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
			if s.Interactive || s.Password == "" || !s.userOK(c.User()) || string(pw) != s.Password {
				return nil, errors.New("sshtest: password rejected")
			}
			return nil, nil
		},
		KeyboardInteractiveCallback: func(c ssh.ConnMetadata, client ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
			if s.Password == "" || !s.userOK(c.User()) {
				return nil, errors.New("sshtest: no interactive auth")
			}
			answers, err := client("", "", []string{"Password: "}, []bool{false})
			if err != nil || len(answers) != 1 || answers[0] != s.Password {
				return nil, errors.New("sshtest: interactive password rejected")
			}
			return nil, nil
		},
	}
	s.config.AddHostKey(hostSigner)
	s.ln, err = net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s.Addr = s.ln.Addr().String()
	go s.accept()
	t.Cleanup(s.Close)
	return s
}

func (s *Server) userOK(user string) bool { return s.User == "" || s.User == user }

func (s *Server) keyOK(k ssh.PublicKey) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, a := range s.accepted {
		if bytes.Equal(a, k.Marshal()) {
			return true
		}
	}
	return false
}

// AcceptKey lets another client key log in too (a bastion shared with the
// nodes behind it).
func (s *Server) AcceptKey(k ssh.PublicKey) {
	s.mu.Lock()
	s.accepted = append(s.accepted, k.Marshal())
	s.mu.Unlock()
}

// Port is the listening port.
func (s *Server) Port() int {
	_, p, _ := net.SplitHostPort(s.Addr)
	n, _ := strconv.Atoi(p)
	return n
}

// KnownHostsLine is the known_hosts entry that accepts this server.
func (s *Server) KnownHostsLine() string {
	return knownhosts.Line([]string{s.Addr}, s.HostKey)
}

// Execs is how many exec requests have been served.
func (s *Server) Execs() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.execs
}

// Dials is how many SSH connections have been accepted.
func (s *Server) Dials() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.dials
}

// DropConnections closes every live connection, as a restarted sshd would.
func (s *Server) DropConnections() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for c := range s.conns {
		c.Close()
		delete(s.conns, c)
	}
}

// Close stops the listener and drops the connections.
func (s *Server) Close() {
	_ = s.ln.Close()
	s.DropConnections()
}

func (s *Server) accept() {
	for {
		nc, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.handle(nc)
	}
}

func (s *Server) handle(nc net.Conn) {
	sconn, chans, reqs, err := ssh.NewServerConn(nc, s.config)
	if err != nil {
		nc.Close()
		return
	}
	s.mu.Lock()
	s.conns[sconn] = struct{}{}
	s.dials++
	s.mu.Unlock()
	go ssh.DiscardRequests(reqs)
	for nch := range chans {
		switch nch.ChannelType() {
		case "session":
			go s.session(nch)
		case "direct-tcpip":
			go s.forward(nch)
		default:
			_ = nch.Reject(ssh.UnknownChannelType, "sshtest")
		}
	}
	s.mu.Lock()
	delete(s.conns, sconn)
	s.mu.Unlock()
}

func (s *Server) session(nch ssh.NewChannel) {
	ch, reqs, err := nch.Accept()
	if err != nil {
		return
	}
	defer ch.Close()
	for req := range reqs {
		switch req.Type {
		case "exec":
			var p struct{ Cmd string }
			_ = ssh.Unmarshal(req.Payload, &p)
			_ = req.Reply(true, nil)
			stdin, _ := io.ReadAll(ch) // the client closes its side after the script
			s.mu.Lock()
			s.execs++
			s.mu.Unlock()
			out, errOut, code := s.handler(p.Cmd, string(stdin))
			_, _ = io.WriteString(ch, out)
			_, _ = io.WriteString(ch.Stderr(), errOut)
			_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{uint32(code)}))
			return
		default:
			if req.WantReply {
				_ = req.Reply(req.Type == "signal" || req.Type == "env", nil)
			}
		}
	}
}

// forward serves a direct-tcpip channel by dialing the requested target.
func (s *Server) forward(nch ssh.NewChannel) {
	var p struct {
		Host     string
		Port     uint32
		OrigHost string
		OrigPort uint32
	}
	if err := ssh.Unmarshal(nch.ExtraData(), &p); err != nil {
		_ = nch.Reject(ssh.ConnectionFailed, err.Error())
		return
	}
	target, err := net.Dial("tcp", net.JoinHostPort(p.Host, strconv.Itoa(int(p.Port))))
	if err != nil {
		_ = nch.Reject(ssh.ConnectionFailed, err.Error())
		return
	}
	ch, reqs, err := nch.Accept()
	if err != nil {
		target.Close()
		return
	}
	go ssh.DiscardRequests(reqs)
	go func() {
		_, _ = io.Copy(ch, target)
		_ = ch.CloseWrite()
	}()
	_, _ = io.Copy(target, ch)
	target.Close()
	ch.Close()
}
