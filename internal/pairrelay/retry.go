package pairrelay

import (
	"errors"
	"net/http"
	"strconv"
	"time"
)

// The HTTP peer is untrusted. Retain only a local category and a bounded delay,
// never its response body, header text, URL or error string.
type rateLimited struct{ delay time.Duration }

func (e *rateLimited) Error() string { return ErrRateLimited.Error() }
func (e *rateLimited) Unwrap() error { return ErrRateLimited }

// RetryDelay is an availability hint, not authorization. Even a malicious
// Retry-After cannot disable local cancellation or defer a retry past 30 seconds.
func RetryDelay(err error) time.Duration {
	var limited *rateLimited
	if errors.As(err, &limited) {
		return limited.delay
	}
	if errors.Is(err, ErrRateLimited) {
		return 5 * time.Second
	}
	return 0
}

func websocketFailure(response *http.Response, now time.Time) error {
	if response == nil || response.StatusCode != http.StatusTooManyRequests {
		return ErrTransport
	}
	delay := 5 * time.Second
	hints := response.Header.Values("Retry-After")
	if len(hints) == 1 && len(hints[0]) <= 64 {
		if seconds, err := strconv.ParseUint(hints[0], 10, 32); err == nil {
			delay = time.Duration(min(seconds, 30)) * time.Second
		} else if until, err := http.ParseTime(hints[0]); err == nil {
			delay = until.Sub(now)
		}
	}
	return &rateLimited{delay: max(5*time.Second, min(delay, 30*time.Second))}
}

func dialFailure(ctxErr, err error) error {
	if ctxErr != nil {
		return ctxErr
	}
	var limited *rateLimited
	if errors.As(err, &limited) {
		return limited
	}
	if errors.Is(err, ErrRateLimited) {
		return ErrRateLimited
	}
	return ErrTransport
}
