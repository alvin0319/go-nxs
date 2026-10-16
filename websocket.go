package nxs

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	mrand "math/rand/v2"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"
)

const (
	maxFrameBytes   = 524288
	maxAssisted     = 32
	wsPingInterval  = 20 * time.Second
	assistedTimeout = 5 * time.Minute
)

var errNoSocket = errors.New("nxs: WebSocket control transport unavailable")

// wsOperations are the operations that may be carried over the WebSocket.
var wsOperations = []string{"heartbeat", "outcomes", "rotate", "retire", "deregister"}

var authHeaders = []string{"nxs-instance-id", "nxs-key-id", "nxs-timestamp", "nxs-signature-version", "nxs-generation", "nxs-sequence", "idempotency-key", "nxs-signature"}

// controlSocket is the optional WebSocket control transport of a Provider.
type controlSocket struct {
	p   *Provider
	url string

	mu       sync.Mutex
	conn     *websocket.Conn
	binding  string
	done     chan struct{}
	pending  string
	replies  chan wsReply
	pinged   bool
	retryAt  time.Time
	failures int
	closed   bool

	// heartbeatAt is when a heartbeat was last carried, which authorizes assisted joins.
	heartbeatAt atomic.Int64
	assisted    atomic.Int32
}

type wsReply struct {
	Kind    string            `json:"kind"`
	ID      string            `json:"id"`
	Status  int               `json:"status"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body"`
}

// newControlSocket returns the WebSocket transport if discovery advertises it, or nil. The
// endpoint is fixed at /v1/nxs/control on the provider origin.
func newControlSocket(p *Provider) (*controlSocket, error) {
	ext, ok := p.disc.Extensions[extensionWebSocket]
	if !ok || ext.Version != 1 {
		return nil, nil
	}
	u, err := url.Parse(p.origin)
	if err != nil {
		return nil, err
	}
	u.Scheme = map[string]string{"http": "ws", "https": "wss"}[u.Scheme]
	u.Path = "/v1/nxs/control"
	return &controlSocket{p: p, url: u.String()}, nil
}

// carrier returns a request carrier for the operation, or nil if it is not carried.
func (s *controlSocket) carrier(op string) func(context.Context, http.Header, []byte) (int, http.Header, []byte, error) {
	if s == nil {
		return nil
	}
	for _, name := range wsOperations {
		if name == op {
			return func(ctx context.Context, h http.Header, body []byte) (int, http.Header, []byte, error) {
				return s.exchange(ctx, op, h, body)
			}
		}
	}
	return nil
}

// exchange carries a signed operation. opMu must be held.
func (s *controlSocket) exchange(ctx context.Context, op string, h http.Header, body []byte) (int, http.Header, []byte, error) {
	conn, done, err := s.connect(ctx)
	if err != nil {
		return 0, nil, nil, err
	}
	headers := make(map[string]string, len(authHeaders))
	for _, name := range authHeaders {
		headers[name] = h.Get(name)
	}
	frame, err := marshal(map[string]any{"kind": "operation", "operation": op, "headers": headers, "body": string(body)})
	if err != nil || len(frame) > maxFrameBytes {
		return 0, nil, nil, errNoSocket
	}
	id := headers["idempotency-key"]
	replies := make(chan wsReply, 1)
	s.mu.Lock()
	s.pending, s.replies = id, replies
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.pending, s.replies = "", nil
		s.mu.Unlock()
	}()

	if err := conn.Write(ctx, websocket.MessageText, frame); err != nil {
		s.lost(conn, err)
		return 0, nil, nil, err
	}
	select {
	case r := <-replies:
		header := http.Header{}
		for k, v := range r.Headers {
			header.Set(k, v)
		}
		if op == "heartbeat" && r.Status/100 == 2 {
			s.heartbeatAt.Store(time.Now().UnixNano())
		}
		return r.Status, header, []byte(r.Body), nil
	case <-done:
		return 0, nil, nil, errNoSocket
	case <-ctx.Done():
		s.lost(conn, ctx.Err())
		return 0, nil, nil, ctx.Err()
	}
}

// connect returns the connection bound to the current registration, dialing it if needed.
func (s *controlSocket) connect(ctx context.Context) (*websocket.Conn, chan struct{}, error) {
	st := s.p.st
	binding := st.Registration.InstanceID + ":" + fmt.Sprint(st.Generation)
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil, nil, errNoSocket
	}
	if s.conn != nil && s.binding == binding {
		conn, done := s.conn, s.done
		s.mu.Unlock()
		return conn, done, nil
	}
	if s.conn != nil {
		old := s.conn
		s.mu.Unlock()
		s.lost(old, errors.New("registration generation changed"))
		s.mu.Lock()
	}
	if time.Now().Before(s.retryAt) {
		s.mu.Unlock()
		return nil, nil, errNoSocket
	}
	s.mu.Unlock()

	h, err := s.p.upgradeHeaders(s.url)
	if err != nil {
		return nil, nil, err
	}
	dialCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	conn, _, err := websocket.Dial(dialCtx, s.url, &websocket.DialOptions{HTTPClient: s.p.client.http, HTTPHeader: h, Subprotocols: []string{Protocol}})
	if err == nil && conn.Subprotocol() != Protocol {
		_ = conn.CloseNow()
		err = errors.New("provider did not select the NXS subprotocol")
	}
	if err != nil {
		s.mu.Lock()
		s.backoff()
		s.mu.Unlock()
		s.p.log.Debug("WebSocket control transport unavailable", "error", err)
		return nil, nil, errNoSocket
	}
	conn.SetReadLimit(maxFrameBytes)

	done := make(chan struct{})
	s.mu.Lock()
	s.conn, s.binding, s.done, s.pinged, s.failures = conn, binding, done, false, 0
	s.mu.Unlock()
	s.p.log.Debug("connected WebSocket control transport")
	go s.read(conn)
	go s.keepAlive(conn, done)
	return conn, done, nil
}

func (s *controlSocket) read(conn *websocket.Conn) {
	for {
		typ, b, err := conn.Read(context.Background())
		if err != nil {
			s.lost(conn, err)
			return
		}
		if typ != websocket.MessageText {
			s.lost(conn, errors.New("unexpected binary message"))
			return
		}
		if string(b) == "pong" {
			s.mu.Lock()
			s.pinged = false
			s.mu.Unlock()
			continue
		}
		var kind struct {
			Kind string `json:"kind"`
		}
		if err := json.Unmarshal(b, &kind); err != nil || kind.Kind == "" {
			s.violation(conn, "frame without kind")
			return
		}
		switch kind.Kind {
		case "assisted-join":
			j, err := decodeAssistedJoin(b)
			if err != nil {
				s.violation(conn, "invalid assisted join frame")
				return
			}
			s.mu.Lock()
			bound := s.conn == conn && s.binding == j.InstanceID+":"+fmt.Sprint(j.Generation)
			s.mu.Unlock()
			if !bound {
				s.violation(conn, "assisted join for another registration")
				return
			}
			go s.assist(conn, j)
			continue
		case "response":
		default:
			continue
		}
		r, err := decodeReply(b)
		if err != nil {
			s.violation(conn, "invalid response frame")
			return
		}
		s.mu.Lock()
		if s.conn == conn && s.replies != nil && r.ID == s.pending {
			s.replies <- r
			s.replies = nil
			s.mu.Unlock()
			continue
		}
		s.mu.Unlock()
		s.lost(conn, errors.New("unexpected response"))
		return
	}
}

// keepAlive sends a ping periodically, and drops the connection if no pong arrives in time.
func (s *controlSocket) keepAlive(conn *websocket.Conn, done chan struct{}) {
	t := time.NewTicker(wsPingInterval)
	defer t.Stop()
	for {
		select {
		case <-done:
			return
		case <-t.C:
		}
		s.mu.Lock()
		missed := s.pinged
		s.pinged = true
		s.mu.Unlock()
		if missed {
			s.lost(conn, errors.New("no pong received"))
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		err := conn.Write(ctx, websocket.MessageText, []byte("ping"))
		cancel()
		if err != nil {
			s.lost(conn, err)
			return
		}
	}
}

// assist answers an assisted join over the connection it arrived on.
func (s *controlSocket) assist(conn *websocket.Conn, j *assistedJoin) {
	result := map[string]any{"kind": "assisted-join-result", "id": j.ID, "accepted": false}
	switch {
	case s.assisted.Add(1) > maxAssisted:
		s.p.log.Warn("rejected assisted join: too many in flight")
	case !s.authorized():
		s.p.log.Warn("rejected assisted join: no recent heartbeat over the WebSocket")
	case time.UnixMilli(j.ExpiresAt).After(s.authorizedUntil()):
		s.p.log.Warn("rejected assisted join: it outlives the authorization of assisted joins")
	default:
		if answer, deadline, err := s.p.assist(s.retirement(conn, j), j); err != nil {
			s.p.log.Warn("assisted join failed", "error", err)
		} else if time.Now().Before(deadline) {
			result["accepted"], result["answer"] = true, answer
			s.p.log.Debug("answered assisted join", "id", j.ID)
		}
	}
	s.assisted.Add(-1)
	frame, _ := marshal(result)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s.mu.Lock()
	current := s.conn == conn
	s.mu.Unlock()
	if current {
		_ = conn.Write(ctx, websocket.MessageText, frame)
	}
}

// retirement returns a context for the peer of an assisted join that arrived on conn. It is
// canceled once conn is no longer the current connection or no longer authorizes assisted
// joins, and at the latest when the peer would have timed out anyway.
func (s *controlSocket) retirement(conn *websocket.Conn, j *assistedJoin) context.Context {
	ctx, cancel := context.WithDeadline(context.Background(), time.UnixMilli(j.ExpiresAt).Add(admitTimeout))
	s.mu.Lock()
	done := s.done
	if s.conn != conn {
		cancel()
	}
	s.mu.Unlock()
	go func() {
		defer cancel()
		t := time.NewTicker(time.Second)
		defer t.Stop()
		for s.authorized() {
			select {
			case <-ctx.Done():
				return
			case <-done:
				return
			case <-t.C:
			}
		}
	}()
	return ctx
}

var (
	replyIDPattern     = regexp.MustCompile(`^[A-Za-z0-9_-]{16,128}$`)
	headerNamePattern  = regexp.MustCompile("^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,128}$")
	replyFields        = []string{"kind", "id", "status", "headers", "body"}
	errDuplicateMember = errors.New("duplicate member")
)

// decodeReply decodes a response frame of the closed WebSocket reply envelope.
func decodeReply(b []byte) (wsReply, error) {
	var (
		r      wsReply
		fields map[string]json.RawMessage
	)
	if err := checkDuplicates(b); err != nil {
		return r, err
	}
	if err := json.Unmarshal(b, &fields); err != nil {
		return r, err
	}
	for _, name := range replyFields {
		if _, ok := fields[name]; !ok {
			return r, fmt.Errorf("missing %s", name)
		}
	}
	if err := json.Unmarshal(b, &r); err != nil {
		return r, err
	}
	if !replyIDPattern.MatchString(r.ID) || r.Status < 200 || r.Status > 599 || len(r.Headers) > 32 || len(r.Body) > maxBodyBytes {
		return r, errors.New("invalid response envelope")
	}
	seen := make(map[string]bool, len(r.Headers))
	for name, value := range r.Headers {
		lower := strings.ToLower(name)
		if !headerNamePattern.MatchString(name) || seen[lower] || len(value) > 1024 || strings.ContainsFunc(value, func(c rune) bool { return c < 0x20 || c == 0x7f }) {
			return r, errors.New("invalid response header")
		}
		seen[lower] = true
	}
	return r, nil
}

// checkDuplicates rejects JSON with an object that repeats a member name.
func checkDuplicates(b []byte) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	type frame struct {
		object bool
		key    bool
		names  map[string]bool
	}
	var stack []*frame
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			return nil
		} else if err != nil {
			return err
		}
		var top *frame
		if len(stack) > 0 {
			top = stack[len(stack)-1]
		}
		switch tok {
		case json.Delim('{'), json.Delim('['):
			if top != nil && top.object {
				top.key = true
			}
			stack = append(stack, &frame{object: tok == json.Delim('{'), key: true, names: map[string]bool{}})
			continue
		case json.Delim('}'), json.Delim(']'):
			stack = stack[:len(stack)-1]
			continue
		}
		if top == nil || !top.object {
			continue
		}
		if top.key {
			name := tok.(string)
			if top.names[name] {
				return errDuplicateMember
			}
			top.names[name] = true
		}
		top.key = !top.key
	}
}

// violation closes conn with the policy violation status for a malformed frame.
func (s *controlSocket) violation(conn *websocket.Conn, reason string) {
	_ = conn.Close(websocket.StatusPolicyViolation, reason)
	s.lost(conn, errors.New(reason))
}

// authorized reports whether a recent heartbeat over the connection authorizes assisted joins.
func (s *controlSocket) authorized() bool {
	return s != nil && time.Now().Before(s.authorizedUntil())
}

// authorizedUntil returns when the authorization of assisted joins lapses.
func (s *controlSocket) authorizedUntil() time.Time {
	return time.Unix(0, s.heartbeatAt.Load()).Add(assistedTimeout)
}

// lost drops conn if it is the current connection.
func (s *controlSocket) lost(conn *websocket.Conn, err error) {
	s.mu.Lock()
	if s.conn != conn {
		s.mu.Unlock()
		return
	}
	s.conn = nil
	s.heartbeatAt.Store(0)
	close(s.done)
	s.backoff()
	s.mu.Unlock()
	_ = conn.CloseNow()
	s.p.log.Debug("WebSocket control transport lost", "error", err)
}

// backoff delays the next connection attempt. s.mu must be held.
func (s *controlSocket) backoff() {
	delay := min(30*time.Second, 500*time.Millisecond<<min(s.failures, 6))
	s.failures++
	s.retryAt = time.Now().Add(delay + mrand.N(delay))
}

func (s *controlSocket) close() {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.closed = true
	conn := s.conn
	s.mu.Unlock()
	if conn != nil {
		s.lost(conn, errors.New("closed"))
		_ = conn.Close(websocket.StatusNormalClosure, "")
	}
}
