package nxs

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	mrand "math/rand/v2"
	"net/http"
	"regexp"
	"strconv"
	"time"
)

// Error is an error returned by the provider.
type Error struct {
	// Status is the HTTP status code.
	Status int
	// Code is the machine-readable error code, if any.
	Code string
	// RetryAfter is the delay requested by the provider, if any.
	RetryAfter time.Duration
}

func (e *Error) Error() string {
	if e.Code != "" {
		return fmt.Sprintf("nxs: provider error %d: %s", e.Status, e.Code)
	}
	return fmt.Sprintf("nxs: provider error %d", e.Status)
}

var errorCodePattern = regexp.MustCompile(`^[a-z0-9_]{1,80}$`)

func (e *Error) retryable() bool {
	switch e.Status {
	case http.StatusTooManyRequests, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	}
	return false
}

// client performs requests against a provider origin.
type client struct {
	origin  string
	http    *http.Client
	maxBody int64
}

func newClient(origin string, base *http.Client) *client {
	c := &http.Client{}
	if base != nil {
		*c = *base
	}
	// Credentials must never follow a redirect.
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &client{origin: origin, http: c, maxBody: 65536}
}

// request describes one provider exchange.
type request struct {
	method, url string
	body        []byte
	bearer      string
	timeout     time.Duration
	attempts    int
	// sign adds the signature headers for a fresh attempt.
	sign func(h http.Header, path string) error
	// carrier, if set, carries a signed attempt before HTTPS is used. It returns an error
	// if the attempt must be made over HTTPS instead.
	carrier func(ctx context.Context, h http.Header, body []byte) (status int, header http.Header, respBody []byte, err error)
}

// do performs req, retrying transient failures, and decodes the response into v.
func (c *client) do(ctx context.Context, req request, v any) error {
	if req.attempts == 0 {
		req.attempts = 3
	}
	if req.timeout == 0 {
		req.timeout = 15 * time.Second
	}
	var err error
	for attempt := 0; attempt < req.attempts; attempt++ {
		if attempt > 0 {
			delay := time.Duration(250<<attempt)*time.Millisecond + mrand.N(250*time.Millisecond)
			var perr *Error
			if errors.As(err, &perr) && perr.RetryAfter > 0 {
				if perr.RetryAfter > 10*time.Second {
					return err
				}
				delay = max(delay, perr.RetryAfter)
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(delay):
			}
		}
		var retry bool
		if retry, err = c.attempt(ctx, req, v); !retry {
			return err
		}
	}
	return err
}

func (c *client) attempt(ctx context.Context, req request, v any) (retry bool, err error) {
	ctx, cancel := context.WithTimeout(ctx, req.timeout)
	defer cancel()
	var body io.Reader
	if req.body != nil {
		body = bytes.NewReader(req.body)
	}
	r, err := http.NewRequestWithContext(ctx, req.method, req.url, body)
	if err != nil {
		return false, err
	}
	r.Header.Set("Accept", "application/json")
	if req.body != nil {
		r.Header.Set("Content-Type", "application/json")
	}
	if req.bearer != "" {
		r.Header.Set("Authorization", "Bearer "+req.bearer)
	}
	if req.sign != nil {
		if err := req.sign(r.Header, r.URL.RequestURI()); err != nil {
			return false, err
		}
	}
	if req.carrier != nil {
		if status, header, b, err := req.carrier(ctx, r.Header, req.body); err == nil {
			return c.response(status, header, b, v)
		}
	}
	resp, err := c.http.Do(r)
	if err != nil {
		return ctx.Err() == nil || errors.Is(ctx.Err(), context.DeadlineExceeded), err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, c.maxBody+1))
	if err != nil {
		return true, err
	}
	return c.response(resp.StatusCode, resp.Header, b, v)
}

// response decodes a provider response into v.
func (c *client) response(status int, header http.Header, b []byte, v any) (retry bool, err error) {
	if int64(len(b)) > c.maxBody {
		return false, errors.New("nxs: provider response too large")
	}
	if status < 200 || status > 299 {
		e := &Error{Status: status}
		var body struct {
			Code string `json:"code"`
		}
		if json.Unmarshal(b, &body) == nil && errorCodePattern.MatchString(body.Code) {
			e.Code = body.Code
		}
		if s, err := strconv.Atoi(header.Get("Retry-After")); err == nil && s >= 0 {
			e.RetryAfter = time.Duration(s) * time.Second
		}
		return e.retryable(), e
	}
	if v == nil {
		return false, nil
	}
	if err := json.Unmarshal(b, v); err != nil {
		return false, fmt.Errorf("nxs: decode provider response: %w", err)
	}
	return false, nil
}

// randomID returns a random URL-safe identifier.
func randomID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
