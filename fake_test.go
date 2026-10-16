package nxs

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/df-mc/go-nxs/admission"
	"github.com/df-mc/go-nxs/internal/canon"
)

// fakeProvider is a minimal NXS provider.
type fakeProvider struct {
	t      *testing.T
	srv    *httptest.Server
	origin string

	mu           sync.Mutex
	keys         []admission.Key
	pub          *ecdsa.PublicKey
	keyID        string
	generation   int64
	challenges   map[string]*challenge
	sequence     int64
	profile      *hostProfile
	heartbeats   []heartbeatRequest
	events       []event
	ws           *websocket.Conn
	wsHeartbeats int
	results      map[string]chan map[string]any
	// fence rejects the next signed request as a stale generation.
	fence bool
	// feedback is returned as connectivity checks in heartbeat responses.
	feedback []connectivityCheck
	// retireAfter is the retirement of the first admission key, if set.
	retireAfter int64
	// delivered records the admission key requests that were answered.
	delivered map[string]bool

	fenced         bool
	fencedRequests int
	forget         bool
	forgetProfile  bool
}

func newFakeProvider(t *testing.T) *fakeProvider {
	f := &fakeProvider{
		t:          t,
		challenges: map[string]*challenge{},
		keys:       []admission.Key{{ID: "K001", Secret: fakeSecret(0)}},
		keyID:      "key_1",
		results:    map[string]chan map[string]any{},
		delivered:  map[string]bool{},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+discoveryPath, f.discovery)
	mux.HandleFunc("POST /v1/nxs/register", f.register)
	mux.HandleFunc("POST /v1/nxs/complete", f.complete)
	mux.HandleFunc("GET /v1/nxs/control", f.control)
	for _, op := range []string{"heartbeat", "outcomes", "rotate", "retire", "deregister", "operator-action"} {
		mux.HandleFunc("POST /v1/nxs/"+op, func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			status, resp := f.operation(op, r.Method, r.URL.RequestURI(), r.Header, body)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			_ = json.NewEncoder(w).Encode(resp)
		})
	}
	f.srv = httptest.NewServer(mux)
	f.origin = f.srv.URL
	t.Cleanup(f.srv.Close)
	return f
}

func fakeSecret(n int) string {
	sum := sha256.Sum256([]byte("fake-provider-secret-" + strconv.Itoa(n)))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func (f *fakeProvider) write(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (f *fakeProvider) key(id string) (admission.Key, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, k := range f.keys {
		if k.ID == id {
			return k, true
		}
	}
	return admission.Key{}, false
}

func (f *fakeProvider) discovery(w http.ResponseWriter, _ *http.Request) {
	f.write(w, http.StatusOK, map[string]any{
		"provider":      f.origin,
		"protocols":     []string{Protocol},
		"signatures":    []string{SignatureVersion},
		"authorization": map[string]any{"schemes": []string{schemeAnonymous}},
		"limits":        map[string]any{"heartbeatIntervalMs": 1000},
		"extensions": map[string]any{
			extensionConnectivity: map[string]any{"version": 1, "critical": false, "data": map[string]any{"stunServers": []any{}}},
			extensionWebSocket:    map[string]any{"version": 1, "critical": false, "data": map[string]any{}},
			"com.example.claim":   map[string]any{"version": 1, "critical": false, "data": map[string]any{"operations": map[string]string{"refresh": f.origin + "/v1/nxs/outcomes"}}},
		},
	})
}

func (f *fakeProvider) register(w http.ResponseWriter, r *http.Request) {
	var req registerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	c := &challenge{Protocol: Protocol, Signature: SignatureVersion, ChallengeID: randomID(), Nonce: "nonce", Audience: f.origin,
		ExpiresAt: time.Now().Add(time.Minute).UnixMilli(), ServerTime: time.Now().UnixMilli()}
	if req.RegistrationID != "" && f.forget {
		f.write(w, http.StatusForbidden, map[string]string{"code": codeRecoveryUnavailable})
		return
	}
	if req.RegistrationID != "" {
		c.Context = challengeContext{Mode: modeRecover, RegistrationID: req.RegistrationID}
	} else {
		f.forget = false
		pub, err := req.PublicKeyJWK.publicKey()
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		f.pub = pub
		c.Context = challengeContext{Mode: modeNewService}
		c.Pow.Difficulty = 4
	}
	c.Thumbprint = publicJWK(f.pub).thumbprint()
	c.ContextDigest, _ = c.Context.digest()
	f.challenges[c.ChallengeID] = c
	f.write(w, http.StatusOK, c)
}

func (f *fakeProvider) complete(w http.ResponseWriter, r *http.Request) {
	var req completeRequest
	_ = json.NewDecoder(r.Body).Decode(&req)
	f.mu.Lock()
	defer f.mu.Unlock()
	c, ok := f.challenges[req.ChallengeID]
	if !ok {
		f.write(w, http.StatusForbidden, map[string]string{"code": "invalid_proof"})
		return
	}
	proof, _ := c.proof(req.ProofNonce, req.IdempotencyKey)
	if !verify(f.pub, proof, req.Signature) || leadingZeroBits(sha256.Sum256(proof)) < c.Pow.Difficulty {
		f.write(w, http.StatusForbidden, map[string]string{"code": "invalid_proof"})
		return
	}
	delete(f.challenges, req.ChallengeID)
	f.sequence = 0
	f.generation++
	reg := registration{Protocol: Protocol, Provider: f.origin, RegistrationID: "reg_1", InstanceID: "instance_1", KeyID: f.keyID,
		LeaseGeneration: f.generation, ServiceID: "svc_1", PublicAddress: "https://test.example",
		Extensions: map[string]extension{"com.example.claim": {Version: 1, Data: json.RawMessage(`{"url":"https://claim.example"}`)}}}
	if c.Context.Mode != modeRecover {
		reg.AdmissionKey = &ticketKey{KeyID: f.keys[0].ID, Secret: f.keys[0].Secret}
		reg.OperatorAction = &operatorAction{URL: "https://claim.example/one-time", Text: "Claim this server", ExpiresAt: time.Now().Add(3 * time.Second).UnixMilli()}
	}
	f.write(w, http.StatusOK, reg)
}

// authenticate verifies the machine signature of an operational request.
func (f *fakeProvider) authenticate(method, path string, h http.Header, body []byte) bool {
	ts, _ := strconv.ParseInt(h.Get("nxs-timestamp"), 10, 64)
	gen, _ := strconv.ParseInt(h.Get("nxs-generation"), 10, 64)
	seq, _ := strconv.ParseInt(h.Get("nxs-sequence"), 10, 64)
	payload, err := requestPayload(f.origin, method, path, ts, h.Get("nxs-instance-id"), h.Get("nxs-key-id"), h.Get("idempotency-key"), gen, seq, body)
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fence && method != http.MethodGet {
		f.fence = false
		return false
	}
	// A WebSocket upgrade reuses the current sequence.
	stale := seq <= f.sequence
	if method == http.MethodGet {
		stale = seq < f.sequence
	}
	if err != nil || !verify(f.pub, payload, h.Get("nxs-signature")) || stale || gen != f.generation ||
		h.Get("nxs-key-id") != f.keyID || h.Get("nxs-signature-version") != SignatureVersion {
		return false
	}
	if method != http.MethodGet {
		f.sequence = seq
	}
	return true
}

// operation handles a signed operation received over HTTPS or the WebSocket.
func (f *fakeProvider) operation(op, method, path string, h http.Header, body []byte) (int, any) {
	f.mu.Lock()
	fenced := f.fenced
	if fenced {
		f.fencedRequests++
	}
	f.mu.Unlock()
	if fenced {
		return http.StatusConflict, map[string]string{"code": codeGenerationFenced}
	}
	if !f.authenticate(method, path, h, body) {
		return http.StatusUnauthorized, map[string]string{"code": "auth_invalid"}
	}
	switch op {
	case "heartbeat":
		return f.heartbeat(body)
	case "outcomes":
		var req struct{ Events []event }
		_ = json.Unmarshal(body, &req)
		f.mu.Lock()
		f.events = append(f.events, req.Events...)
		f.mu.Unlock()
	case "rotate":
		var req struct {
			PublicKeyJwk jwk    `json:"publicKeyJwk"`
			Proof        string `json:"proof"`
		}
		_ = json.Unmarshal(body, &req)
		pub, err := req.PublicKeyJwk.publicKey()
		f.mu.Lock()
		defer f.mu.Unlock()
		proof, _ := canon.Array(Protocol, "rotate", f.origin, h.Get("nxs-instance-id"), f.keyID, req.PublicKeyJwk.thumbprint(), f.generation, h.Get("idempotency-key"))
		if err != nil || !verify(pub, proof, req.Proof) {
			return http.StatusUnauthorized, map[string]string{"code": "replacement_proof_invalid"}
		}
		f.pub, f.keyID = pub, "key_2"
		return http.StatusOK, map[string]string{"keyId": f.keyID}
	case "operator-action":
		return http.StatusOK, map[string]any{"operatorAction": operatorAction{URL: "https://claim.example/fresh", Text: "Claim this server", ExpiresAt: time.Now().Add(time.Hour).UnixMilli()}}
	}
	return http.StatusOK, map[string]any{}
}

func (f *fakeProvider) heartbeat(body []byte) (int, any) {
	var req heartbeatRequest
	if err := json.Unmarshal(body, &req); err != nil {
		f.t.Errorf("decode heartbeat: %v", err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.heartbeats = append(f.heartbeats, req)
	if req.HostProfile != nil {
		f.profile = req.HostProfile
	}
	rev := "rev_" + strconv.Itoa(len(f.heartbeats))
	if req.HostProfile == nil {
		rev = req.HostProfileRevision
		if f.forgetProfile {
			f.forgetProfile, rev = false, "rev_other"
		}
	}
	resp := heartbeatResponse{HostProfileRevision: &rev, Readiness: Readiness{Routable: req.AcceptingPlayers, Reasons: []string{}},
		CheckIn: &checkIn{AfterMillis: 1000, LeaseMillis: 30000, MinUpdateIntervalMillis: 1000}, OperatorActionAvailable: true}
	resp.AdmissionKeyRetirements = []struct {
		KeyID       string `json:"keyId"`
		RetireAfter int64  `json:"retireAfter"`
	}{}
	if f.retireAfter != 0 {
		resp.AdmissionKeyRetirements = append(resp.AdmissionKeyRetirements, struct {
			KeyID       string `json:"keyId"`
			RetireAfter int64  `json:"retireAfter"`
		}{f.keys[0].ID, f.retireAfter})
	}
	if req.AdmissionKeyRequestID != "" && !f.delivered[req.AdmissionKeyRequestID] {
		f.delivered[req.AdmissionKeyRequestID] = true
		k := admission.Key{ID: fmt.Sprintf("K%03d", len(f.keys)+1), Secret: fakeSecret(len(f.keys))}
		f.keys = append(f.keys, k)
		resp.AdmissionKeyRequest = &struct {
			ID    string `json:"id"`
			KeyID string `json:"keyId"`
		}{req.AdmissionKeyRequestID, k.ID}
		resp.AdmissionKey = &ticketKey{KeyID: k.ID, Secret: k.Secret}
	}
	if f.feedback != nil {
		var data struct {
			CandidateRevision int64 `json:"candidateRevision"`
		}
		_ = json.Unmarshal(req.Extensions[extensionConnectivity].Data, &data)
		b, _ := json.Marshal(map[string]any{"method": "defined", "candidateRevision": data.CandidateRevision, "checks": f.feedback})
		resp.Extensions = map[string]extension{extensionConnectivity: {Version: 1, Data: b}}
	}
	return http.StatusOK, resp
}

// control serves the WebSocket control transport.
func (f *fakeProvider) control(w http.ResponseWriter, r *http.Request) {
	if !f.authenticate(http.MethodGet, r.URL.RequestURI(), r.Header, nil) {
		f.write(w, http.StatusUnauthorized, map[string]string{"code": "auth_invalid"})
		return
	}
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{Protocol}})
	if err != nil {
		return
	}
	f.mu.Lock()
	f.ws = conn
	f.mu.Unlock()
	for {
		_, b, err := conn.Read(context.Background())
		if err != nil {
			return
		}
		if string(b) == "ping" {
			_ = conn.Write(context.Background(), websocket.MessageText, []byte("pong"))
			continue
		}
		var msg struct {
			Kind      string            `json:"kind"`
			ID        string            `json:"id"`
			Operation string            `json:"operation"`
			Headers   map[string]string `json:"headers"`
			Body      string            `json:"body"`
		}
		if err := json.Unmarshal(b, &msg); err != nil {
			f.t.Errorf("decode control frame: %v", err)
			return
		}
		if msg.Kind == "assisted-join-result" {
			var result map[string]any
			_ = json.Unmarshal(b, &result)
			f.mu.Lock()
			ch := f.results[msg.ID]
			f.mu.Unlock()
			if ch != nil {
				ch <- result
			}
			continue
		}
		h := http.Header{}
		for k, v := range msg.Headers {
			h.Set(k, v)
		}
		status, resp := f.operation(msg.Operation, http.MethodPost, "/v1/nxs/"+msg.Operation, h, []byte(msg.Body))
		if msg.Operation == "heartbeat" {
			f.mu.Lock()
			f.wsHeartbeats++
			f.mu.Unlock()
		}
		out, _ := json.Marshal(resp)
		reply, _ := json.Marshal(wsReply{Kind: "response", ID: h.Get("idempotency-key"), Status: status, Headers: map[string]string{"content-type": "application/json"}, Body: string(out)})
		_ = conn.Write(context.Background(), websocket.MessageText, reply)
	}
}

// assist sends an assisted join to the host and returns its answer.
func (f *fakeProvider) assist(ctx context.Context, join map[string]any) (string, error) {
	id, ok := join["id"].(string)
	if !ok {
		id = randomID()
	}
	join["kind"], join["version"], join["id"] = "assisted-join", 1, id
	ch := make(chan map[string]any, 1)
	f.mu.Lock()
	conn := f.ws
	f.results[id] = ch
	f.mu.Unlock()
	if conn == nil {
		return "", errors.New("host is not connected over WebSocket")
	}
	b, _ := json.Marshal(join)
	if err := conn.Write(ctx, websocket.MessageText, b); err != nil {
		return "", err
	}
	select {
	case r := <-ch:
		if r["accepted"] != true {
			return "", errors.New("assisted join rejected")
		}
		return r["answer"].(string), nil
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

func (f *fakeProvider) lastHeartbeat() heartbeatRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.heartbeats[len(f.heartbeats)-1]
}

func (f *fakeProvider) countEvents(stage string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, e := range f.events {
		if e.Stage == stage {
			n++
		}
	}
	return n
}
