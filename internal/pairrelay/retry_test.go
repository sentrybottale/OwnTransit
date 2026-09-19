package pairrelay

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRateLimitHintsAreBoundedAndRedacted(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	for _, tc := range []struct {
		hint string
		want time.Duration
	}{
		{"", 5 * time.Second}, {"0", 5 * time.Second}, {"-1", 5 * time.Second},
		{"12", 12 * time.Second}, {"3600", 30 * time.Second},
		{"999999999999999999999999999999999999", 5 * time.Second},
		{"private-test-value", 5 * time.Second}, {strings.Repeat("9", 200), 5 * time.Second},
		{now.Add(17 * time.Second).Format(http.TimeFormat), 17 * time.Second},
		{now.Add(-time.Hour).Format(http.TimeFormat), 5 * time.Second},
		{now.Add(time.Hour).Format(http.TimeFormat), 30 * time.Second},
	} {
		response := &http.Response{StatusCode: http.StatusTooManyRequests, Header: http.Header{"Retry-After": []string{tc.hint}}}
		err := websocketFailure(response, now)
		if !errors.Is(err, ErrRateLimited) || !errors.Is(err, ErrTransport) || RetryDelay(err) != tc.want {
			t.Fatalf("rate limit classification/bound: got %v, %v; want %v", err, RetryDelay(err), tc.want)
		}
		if strings.Contains(err.Error(), "private-test-value") {
			t.Fatal("peer input leaked")
		}
	}
	for _, response := range []*http.Response{nil, {StatusCode: 403}, {StatusCode: 302}} {
		if err := websocketFailure(response, now); !errors.Is(err, ErrTransport) || RetryDelay(err) != 0 {
			t.Fatal("unrelated response granted retry hint")
		}
	}
}

func TestDialErrorClassificationSurvivesPublicAndRuntimeClients(t *testing.T) {
	err429 := websocketFailure(&http.Response{StatusCode: 429, Header: http.Header{"Retry-After": []string{"9"}}}, time.Now())
	dial := func(context.Context, string) (net.Conn, error) { return nil, err429 }
	public, err := NewPublicClient("wss://relay.example/connects", dial)
	if err != nil {
		t.Fatal(err)
	}
	_, err = public.FetchServerInfo(context.Background())
	if !errors.Is(err, ErrRateLimited) || RetryDelay(err) != 9*time.Second {
		t.Fatal("public operation lost rate limit")
	}
	e := &endpoint{dial: dial}
	_, err = e.open(context.Background(), kindRuntime)
	if !errors.Is(err, ErrRateLimited) || RetryDelay(err) != 9*time.Second {
		t.Fatal("runtime lost rate limit")
	}
	// An injected/private network error is never preserved as diagnostic text.
	e.dial = func(context.Context, string) (net.Conn, error) { return nil, errors.New("private-test-value") }
	_, err = e.open(context.Background(), kindRuntime)
	if err != ErrTransport {
		t.Fatal("raw dial error escaped")
	}
}

func TestWebSocketUpgradePreservesHTTPRateLimitOnly(t *testing.T) {
	for _, status := range []int{429, 403, 503} {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Retry-After", "8")
			http.Error(w, "private-test-response-never-display", status)
		}))
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		c, err := websocketUpgrade(ctx, "wss"+strings.TrimPrefix(server.URL, "https"), server.Client())
		cancel()
		server.Close()
		if c != nil || !errors.Is(err, ErrTransport) || strings.Contains(err.Error(), "private-test") {
			t.Fatal("HTTP rejection lost/redaction failed")
		}
		if status == 429 && (!errors.Is(err, ErrRateLimited) || RetryDelay(err) != 8*time.Second) {
			t.Fatal("actual HTTP 429 lost its category")
		}
		if status != 429 && RetryDelay(err) != 0 {
			t.Fatal("non-rate response supplied scheduling hint")
		}
	}
	response := &http.Response{StatusCode: 429, Header: http.Header{"Retry-After": []string{"8", "30"}}}
	if RetryDelay(websocketFailure(response, time.Now())) != 5*time.Second {
		t.Fatal("ambiguous retry header accepted")
	}
}
