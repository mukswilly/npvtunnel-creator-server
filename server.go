package main

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"time"
)

// Server is the HTTP API surface. State is held in [State]; this type is
// stateless other than the logger reference.
type Server struct {
	state  *State
	logger *slog.Logger
	// inFlight bounds concurrently-served requests. A buffered channel
	// acts as a semaphore: a full channel means the server is at capacity
	// and sheds load with 503 rather than letting goroutines / file
	// descriptors grow without bound under a flood. Sized once at
	// construction (maxInFlightRequests).
	inFlight chan struct{}
}

// maxInFlightRequests caps concurrently-served requests. Generous for a
// single small VPS serving one creator's audience (issue calls are cached
// client-side to roughly once per config TTL), tight enough that a
// flood can't exhaust goroutines or file descriptors. /healthz bypasses
// the limit so a liveness probe still succeeds while the server sheds load.
const maxInFlightRequests = 256

func NewServer(state *State, logger *slog.Logger) *Server {
	return &Server{
		state:    state,
		logger:   logger,
		inFlight: make(chan struct{}, maxInFlightRequests),
	}
}

// Router returns the http.Handler for the public endpoints.
func (s *Server) Router() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/issue", s.handleIssue)
	mux.HandleFunc("POST /v1/redeem", s.handleRedeem)
	mux.HandleFunc("GET /v1/creator-pubkey", s.handleCreatorPubKey)
	mux.HandleFunc("GET /healthz", s.handleHealth)
	return s.limitInFlight(mux)
}

// limitInFlight is the concurrency-limiting middleware (see
// maxInFlightRequests). /healthz bypasses it so liveness checks aren't
// starved when the server is saturated.
func (s *Server) limitInFlight(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			next.ServeHTTP(w, r)
			return
		}
		select {
		case s.inFlight <- struct{}{}:
			defer func() { <-s.inFlight }()
			next.ServeHTTP(w, r)
		default:
			w.Header().Set("Retry-After", "1")
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{
				"error":  "server_busy",
				"detail": "server is at capacity; retry shortly",
			})
		}
	})
}

// handleCreatorPubKey exposes the server's signing pubkey for test/dev. In
// production the recipient pins this value from the discovery envelope and
// doesn't need to hit this endpoint.
func (s *Server) handleCreatorPubKey(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"creatorPubkey": s.state.CreatorPubKeyCompressedB64(),
	})
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok\n"))
}

// handleIssue implements POST /v1/issue.
//
// Flow:
//
//  1. Parse + validate request shape; verify ECDSA over the canonical
//     signing input against req.DevicePk.
//  2. Look up the ConfigEntry by req.ConfigID (404 if unknown).
//  3. Apply per-(device, config) rate limit.
//  4. Evaluate attestation policy; reject / shorten TTL as configured.
//  5. base64url-no-pad the routed entry's static ConfigBody → ConfigB64.
//  6. Sign the receipt (covers devicePk, requestNonce, expiresAt, ConfigB64).
//  7. Emit the audit record and return 200 with IssueResponse.
func (s *Server) handleIssue(w http.ResponseWriter, r *http.Request) {
	// Hot-reload configs.json if it changed since last load, so editing it
	// takes effect without a restart. A bad edit keeps the last-good
	// registry live (logged, not fatal).
	if err := s.state.ReloadConfigsIfChanged(); err != nil {
		s.logger.Warn("configs.json reload failed", "err", err.Error())
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 64*1024))
	if err != nil {
		writeIssueError(w, http.StatusBadRequest, "bad_request", "read body: "+err.Error())
		return
	}
	var req IssueRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeIssueError(w, http.StatusBadRequest, "bad_request", "parse json: "+err.Error())
		return
	}

	if req.V != 1 {
		writeIssueError(w, http.StatusBadRequest, "unsupported_version", "this server speaks v1")
		return
	}
	if req.DevicePk == "" || req.RequestNonce == "" || req.RequestSignature == "" || req.ConfigID == "" {
		writeIssueError(w, http.StatusBadRequest, "bad_request", "missing required field")
		return
	}

	ok, sigErr := verifyIssueRequestSignature(&req)
	if sigErr != nil {
		writeIssueError(w, http.StatusBadRequest, "bad_signature", sigErr.Error())
		return
	}
	if !ok {
		writeIssueError(w, http.StatusUnauthorized, "bad_signature", "request signature did not verify")
		return
	}

	// Replay note: req.RequestNonce is NOT tracked server-side, and the
	// signing input carries no timestamp, so a captured signed request is
	// replayable indefinitely. The nonce's only job is to bind the
	// RECEIPT to this specific request (see issueReceiptSigningInput) — it
	// is not a server-side anti-replay store. This is acceptable because a
	// replayed request only ever returns the same config already addressed
	// to req.DevicePk; a party that isn't that device gains nothing from
	// re-fetching it, and volume is capped by the per-(device,config) rate
	// limit below. Genuine request-replay resistance would need a signed
	// issuedAt + acceptance window — a breaking wire change requiring a
	// coordinated rollout, deliberately not done here.

	// Look up the registered config. If a config registry is loaded but the
	// requested fp is not in it, return 404. If no registry is loaded
	// (configs.json absent / ephemeral mode), fall back to a stub
	// ConfigBody so the wire-protocol harness keeps working without a
	// registry.
	var configJson json.RawMessage
	var attestationPolicy *AttestationPolicy
	// Baseline config lifetime. Per-config override from the entry
	// (resolveConfigTtl) when a registry is loaded; defaultConfigTtl in the
	// no-registry stub path below.
	baseTtl := defaultConfigTtl
	if s.state.HasConfigRegistry() {
		entry := s.state.ConfigByID(req.ConfigID)
		if entry == nil {
			writeIssueError(w, http.StatusNotFound, "config_not_found",
				"this issuer does not know about that configId")
			return
		}
		attestationPolicy = entry.AttestationPolicy
		configJson = entry.Config
		baseTtl = resolveConfigTtl(entry)
	} else {
		// Stub ConfigBody for ephemeral / no-registry mode. Carries no
		// config secret — the wire-protocol harness checks shape + signing,
		// not the contents.
		configJson = json.RawMessage(
			`{"name":"stub","address":"stub.creator-server.example:443","type":"V2RAY","v2rayProfile":{"server":"stub.creator-server.example","serverPort":"443"}}`)
	}

	// Always-on per-(device, config) issuance rate limit. This is the
	// baseline anti-abuse gate and it does NOT depend on any attestation
	// policy — a default deployment is throttled out of the box. The key
	// is (devicePk, configId): independent quotas per config so a device
	// can't dodge the cap by spreading requests across a creator's
	// configs, and keyed on the DEVICE key rather than the source IP so
	// users sharing one carrier / CGNAT address (common in censored
	// regions) are not collectively throttled. An attestation policy may
	// raise the cap; absent one, defaultIssuanceLimitPerHour applies.
	limit := defaultIssuanceLimitPerHour
	if pl := resolveIssuanceLimit(attestationPolicy); pl > 0 {
		limit = pl
	}
	if limit > 0 {
		limiterKey := req.DevicePk + "|" + req.ConfigID
		decision := s.state.issuanceLimiter.Allow(limiterKey, limit, 1*time.Hour)
		if !decision.Allowed {
			retryAfterSec := int(decision.RetryAfter.Seconds() + 0.5)
			if retryAfterSec < 1 {
				retryAfterSec = 1
			}
			policyMode := ""
			if attestationPolicy != nil {
				policyMode = attestationPolicy.Mode
			}
			auditEmit(s.logger, s.state.AuditSalt,
				"issue.rate_limited",
				req.DevicePk,
				shortBase64(req.ConfigID),
				policyMode, req.Attestation.Platform, req.Attestation.Token != "", 0,
				"retryAfterSec", retryAfterSec,
				"limit", limit,
			)
			w.Header().Set("Retry-After", strconv.Itoa(retryAfterSec))
			writeJSON(w, http.StatusTooManyRequests, IssueError{
				Error:      "rate_limited",
				Detail:     "issuance rate limit exceeded for this device + config",
				RetryAfter: retryAfterSec,
			})
			return
		}
	}

	// Apply the creator's attestation policy. Modes: strict rejects
	// unattested; soft shortens TTL; observe logs only; off is a no-op.
	// When the policy names a Verifier, its Verdict
	// supersedes the claimed-only check.
	// Resolve the named verifier from the registry. An unknown name
	// would have failed at configs.json load time, so by this point
	// either we have a real verifier or the policy didn't ask for one.
	var verifier AttestationVerifier
	if attestationPolicy != nil && attestationPolicy.Verifier != "" {
		var err error
		verifier, err = s.state.verifierRegistry.Lookup(attestationPolicy.Verifier)
		if err != nil {
			// Defensive: should be unreachable thanks to load-time
			// validation. If we somehow get here, fail closed rather
			// than silently degrading to no-verifier behavior.
			writeIssueError(w, http.StatusInternalServerError, "server_error",
				"resolve verifier: "+err.Error())
			return
		}
	}

	decision := evaluateAttestationPolicy(attestationPolicy, req.Attestation, verifier, baseTtl)
	policyMode := ""
	if attestationPolicy != nil {
		policyMode = attestationPolicy.Mode
	}
	if decision.reject {
		extras := []any{}
		if decision.rejectReason != "" {
			extras = append(extras, "rejectReason", decision.rejectReason)
		}
		if decision.verdict != nil {
			extras = append(extras,
				"verdictSecurityLevel", decision.verdict.SecurityLevel,
				"verdictHardwareBacked", decision.verdict.HardwareBacked,
				"verdictTrustedRoot", decision.verdict.TrustedRoot,
				"verdictVerifiedBootState", decision.verdict.VerifiedBootState,
				"verdictDeviceLocked", decision.verdict.DeviceLocked,
			)
		}
		auditEmit(s.logger, s.state.AuditSalt,
			"issue.attestation_rejected",
			req.DevicePk,
			shortBase64(req.ConfigID),
			policyMode, req.Attestation.Platform, req.Attestation.Token != "", 0,
			extras...,
		)
		detail := "this config requires attestation; client sent none"
		if decision.rejectReason != "" {
			detail = decision.rejectReason
		}
		writeIssueError(w, http.StatusUnauthorized, "attestation_failed", detail)
		return
	}
	if decision.logAttestation {
		auditEmit(s.logger, s.state.AuditSalt,
			"issue.attestation_observed",
			req.DevicePk,
			shortBase64(req.ConfigID),
			policyMode, req.Attestation.Platform, req.Attestation.Token != "", int(decision.ttl.Seconds()),
		)
	}

	// TTL comes from the attestation-policy decision: the per-config
	// baseline (resolveConfigTtl) in most modes; shorter under "soft" +
	// unattested. Since the issuer doesn't run the data plane, this is a
	// recipient re-fetch cadence carried in expiresAt, not a server-side
	// config expiry.
	expiresAt := time.Now().UTC().Add(decision.ttl).Format(time.RFC3339)

	// The routed entry's ConfigBody already holds the operator's static,
	// already-working config. Return it verbatim — no per-request
	// config derivation or substitution.
	resp := IssueResponse{
		ConfigB64: b64url.EncodeToString(configJson),
		ExpiresAt: expiresAt,
	}

	receiptSig, err := signReceipt(s.state.CreatorSigningKey, req.DevicePk, req.RequestNonce, &resp)
	if err != nil {
		writeIssueError(w, http.StatusInternalServerError, "server_error", "sign receipt: "+err.Error())
		return
	}
	resp.ReceiptSig = receiptSig

	auditEmit(s.logger, s.state.AuditSalt,
		"issue.granted",
		req.DevicePk,
		shortBase64(req.ConfigID),
		policyMode, req.Attestation.Platform, req.Attestation.Token != "", int(decision.ttl.Seconds()),
		"expiresAt", expiresAt,
	)
	writeJSON(w, http.StatusOK, resp)
}

// writeIssueError emits an IssueError with the chosen HTTP status.
func writeIssueError(w http.ResponseWriter, status int, code, detail string) {
	writeJSON(w, status, IssueError{Error: code, Detail: detail})
}

// shortBase64 truncates for log readability. Pubkeys/nonces are not secret —
// this is purely a cosmetic shortener so log lines don't wrap.
func shortBase64(s string) string {
	if len(s) <= 12 {
		return s
	}
	return s[:8] + "…" + s[len(s)-4:]
}

// writeJSON serializes v as JSON, falling back to a 500 on encoding error.
// Suppresses the io.ErrClosedPipe / context.Canceled cases that occur when
// the client disconnected mid-write — those aren't server bugs.
func writeJSON(w http.ResponseWriter, status int, v any) {
	buf, err := json.Marshal(v)
	if err != nil {
		http.Error(w, "encode: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if _, err := w.Write(buf); err != nil && !errors.Is(err, io.ErrClosedPipe) {
		// Logged at the caller level — keep this branch quiet to avoid
		// noise from clients that hang up early.
	}
}
