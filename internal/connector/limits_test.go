package connector

import (
	"context"
	"testing"
	"time"
)

func TestOpenLimiterIsOnePerSecondWithBurstFour(t *testing.T) {
	now := time.Unix(1_000, 0)
	limiter := newOpenLimiter(func() time.Time { return now })
	for index := 0; index < 4; index++ {
		if !limiter.Allow() {
			t.Fatalf("initial request %d was denied", index)
		}
	}
	if limiter.Allow() {
		t.Fatal("fifth immediate request was allowed")
	}
	now = now.Add(999 * time.Millisecond)
	if limiter.Allow() {
		t.Fatal("token refilled before one second")
	}
	now = now.Add(time.Millisecond)
	if !limiter.Allow() {
		t.Fatal("one token did not refill after one second")
	}
	now = now.Add(20 * time.Second)
	for index := 0; index < 4; index++ {
		if !limiter.Allow() {
			t.Fatalf("refilled burst request %d was denied", index)
		}
	}
	if limiter.Allow() {
		t.Fatal("refill exceeded burst four")
	}
}

func TestReconnectBackoffIsBoundedAndExponential(t *testing.T) {
	fixture := newConnectorFixture(t)
	root, cancel := context.WithCancel(context.Background())
	var delays []time.Duration
	fixture.service.jitter = func(value time.Duration) time.Duration { return value }
	fixture.service.sleep = func(_ context.Context, value time.Duration) bool {
		delays = append(delays, value)
		if len(delays) == 4 {
			cancel()
			return false
		}
		return true
	}
	if err := fixture.service.Run(root); err != nil {
		t.Fatalf("Run: %v", err)
	}
	want := []time.Duration{10 * time.Millisecond, 20 * time.Millisecond, 40 * time.Millisecond, 40 * time.Millisecond}
	if len(delays) != len(want) {
		t.Fatalf("backoff delays = %v, want %v", delays, want)
	}
	for index := range want {
		if delays[index] != want[index] {
			t.Fatalf("backoff delays = %v, want %v", delays, want)
		}
	}
}

func TestSemaphoresNeverExceedConfiguredCapacity(t *testing.T) {
	fixture := newConnectorFixture(t)
	for index := 0; index < cap(fixture.service.pending); index++ {
		if !tryAcquire(fixture.service.pending) {
			t.Fatalf("pending slot %d was unexpectedly unavailable", index)
		}
	}
	if tryAcquire(fixture.service.pending) {
		t.Fatal("pending semaphore exceeded capacity")
	}
	for index := 0; index < cap(fixture.service.pending); index++ {
		release(fixture.service.pending)
	}

	for index := 0; index < cap(fixture.service.active); index++ {
		if !tryAcquire(fixture.service.active) {
			t.Fatalf("active slot %d was unexpectedly unavailable", index)
		}
	}
	if tryAcquire(fixture.service.active) {
		t.Fatal("active semaphore exceeded capacity")
	}
	for index := 0; index < cap(fixture.service.active); index++ {
		release(fixture.service.active)
	}
}
