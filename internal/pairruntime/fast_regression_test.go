//go:build darwin || linux

package pairruntime

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/sentrybottale/owntransit/internal/leasewire"
	"github.com/sentrybottale/owntransit/internal/pairrelay"
	"golang.org/x/crypto/ssh"
)

func TestConcurrentQuietSSHSurvivesPendingTimeoutAndReceiverRestart(t *testing.T) {
	f := newIntegratedWithLimits(t, pairrelay.Limits{HandshakeTimeout: time.Second, PairingTimeout: 2 * time.Second})
	stop, done := f.start(t)
	f.pair(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	type opened struct {
		carrier *leasewire.Conn
		release func()
		err     error
	}
	ready := make(chan opened, 2)
	start := make(chan struct{})
	for n := 0; n < 2; n++ {
		go func() { <-start; c, r, e := OpenClient(ctx, f.clientPath, f.dial); ready <- opened{c, r, e} }()
	}
	close(start)
	var clients []*ssh.Client
	for n := 0; n < 2; n++ {
		result := <-ready
		if result.err != nil {
			t.Fatal(result.err)
		}
		defer result.release()
		defer result.carrier.Close()
		conn, channels, requests, err := ssh.NewClientConn(result.carrier, "fixture", &ssh.ClientConfig{User: "fixture", HostKeyCallback: ssh.FixedHostKey(f.sshSigner.PublicKey())})
		if err != nil {
			t.Fatal(err)
		}
		client := ssh.NewClient(conn, channels, requests)
		defer client.Close()
		clients = append(clients, client)
	}
	// Cross the pending boundary with TWO quiet live streams; the independent
	// leasewire tests exercise several shortened renewal/expiry periods.
	time.Sleep(2200 * time.Millisecond)
	var wg sync.WaitGroup
	errors := make(chan error, len(clients))
	for _, client := range clients {
		wg.Add(1)
		go func(client *ssh.Client) {
			defer wg.Done()
			s, err := client.NewSession()
			if err != nil {
				errors <- err
				return
			}
			defer s.Close()
			output, err := s.Output("fixture")
			if err == nil && string(output) != "owntransit-e2e-ok\n" {
				err = ErrState
			}
			errors <- err
		}(client)
	}
	wg.Wait()
	for range clients {
		if err := <-errors; err != nil {
			t.Fatal(err)
		}
	}
	stop()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("receiver shutdown did not complete")
	}
	_, _ = f.start(t)
	for _, path := range []string{f.serverPath, f.clientPath} {
		p, err := ReadPolicy(path)
		if err != nil || p.Locked {
			t.Fatal("ordinary restart changed alarm state")
		}
	}
	f.assertSSH(t)
}
