package sessionguard

import (
	"bytes"
	"errors"
	"net"
	"testing"
	"time"
)

type deadlineConn struct {
	net.Conn
	deadline time.Time
}

func (connection *deadlineConn) SetDeadline(value time.Time) error {
	connection.deadline = value
	return nil
}

func TestGuardRefreshesIdleWithoutCrossingLifetime(t *testing.T) {
	now := time.Unix(1_000, 0)
	left := new(deadlineConn)
	right := new(deadlineConn)
	guard, err := newWithClock(left, right, 5*time.Minute, 10*time.Minute, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	if err := guard.Arm(); err != nil {
		t.Fatal(err)
	}
	if want := now.Add(5 * time.Minute); left.deadline != want || right.deadline != want {
		t.Fatalf("initial deadlines = %v, %v; want %v", left.deadline, right.deadline, want)
	}

	now = now.Add(9 * time.Minute)
	buffer := make([]byte, 1)
	if count, err := guard.Reader(bytes.NewReader([]byte{'x'})).Read(buffer); count != 1 || err != nil {
		t.Fatalf("activity read = %d, %v", count, err)
	}
	if want := time.Unix(1_000, 0).Add(10 * time.Minute); left.deadline != want || right.deadline != want {
		t.Fatalf("clamped deadlines = %v, %v; want %v", left.deadline, right.deadline, want)
	}
}

func TestGuardRefusesActivityAtAbsoluteExpiry(t *testing.T) {
	now := time.Unix(2_000, 0)
	guard, err := newWithClock(new(deadlineConn), new(deadlineConn), time.Minute, time.Minute, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Minute)
	buffer := make([]byte, 1)
	count, err := guard.Reader(bytes.NewReader([]byte{'x'})).Read(buffer)
	if count != 1 || !errors.Is(err, ErrLifetime) {
		t.Fatalf("expired read = %d, %v; want one byte and ErrLifetime", count, err)
	}
}

func TestGuardRejectsInvalidBounds(t *testing.T) {
	connection := new(deadlineConn)
	for _, limits := range [][2]time.Duration{{0, time.Minute}, {time.Minute, 0}, {2 * time.Minute, time.Minute}} {
		if _, err := New(connection, connection, limits[0], limits[1]); err == nil {
			t.Fatalf("accepted idle=%s lifetime=%s", limits[0], limits[1])
		}
	}
}
