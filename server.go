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

// Server holds the HTTP handlers' shared dependencies and a concurrency gate.
type Server struct {
	state  *State
	logger *slog.Logger

	inFlight              chan struct{}
	attestationChallenges *attestationChallengeManager
	requestReplay         *replayCache
}

// maxInFlightRequests caps concurrent non-health requests; excess requests get
// 503 rather than piling up unbounded.
const maxInFlightRequests = 256

func NewServer(state *State, logger *slog.Logger) *Server {
	return &Server{
		state:                 state,
		logger:                logger,
		inFlight:              make(chan struct{}, maxInFlightRequests),
		attestationChallenges: newAttestationChallengeManager(),
		requestReplay:         newReplayCache(),
	}
}

// Router wires the HTTP routes and wraps them in the in-flight limiter.
func (s *Server) Router() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/issue", s.handleIssue)
	mux.HandleFunc("GET /v1/attestation-challenge", s.handleAttestationChallenge)
	mux.HandleFunc("POST /v1/redeem", s.handleRedeem)
	mux.HandleFunc("GET /v1/creator-pubkey", s.handleCreatorPubKey)
	mux.HandleFunc("GET /healthz", s.handleHealth)
	return s.limitInFlight(mux)
}

func (s *Server) handleAttestationChallenge(w http.ResponseWriter, _ *http.Request) {
	challenge, expiresAt, err := s.attestationChallenges.Current(time.Now())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	writeJSON(w, http.StatusOK, AttestationChallenge{
		Challenge: b64url.EncodeToString(challenge),
		ExpiresAt: expiresAt.UTC().Format(time.RFC3339),
	})
}

// limitInFlight admits at most maxInFlightRequests concurrent requests via a
// buffered-channel semaphore, returning 503 with Retry-After when full. /healthz
// is exempt so liveness checks succeed even under load.
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

// handleCreatorPubKey returns this issuer's creator public key so callers can
// pin it out of band.
func (s *Server) handleCreatorPubKey(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"creatorPubkey": s.state.CreatorPubKeyCompressedB64(),
	})
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok\n"))
}

// handleIssue serves POST /v1/issue: a device requests the config registered
// under req.ConfigID. The flow is: pick up any live config edits, parse and
// validate the request, verify its signature, resolve the config and its
// policy, enforce the per-device+config rate limit, evaluate attestation, then
// return the config payload with a signed receipt.
func (s *Server) handleIssue(w http.ResponseWriter, r *http.Request) {

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

	if req.V != 1 && req.V != 2 {
		writeIssueError(w, http.StatusBadRequest, "unsupported_version", "this server speaks v1 and v2")
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
	if req.V >= 2 {
		nonce, nerr := b64url.DecodeString(req.RequestNonce)
		if nerr != nil || len(nonce) != 16 {
			writeIssueError(w, http.StatusBadRequest, "bad_request", "requestNonce must be 16 bytes")
			return
		}
		replayKey := req.DevicePk + "|" + req.ConfigID + "|" + req.RequestNonce
		if !s.requestReplay.Use(replayKey, time.Now(), 25*time.Hour) {
			writeIssueError(w, http.StatusConflict, "replayed_request", "request nonce was already used")
			return
		}
	}

	entry := s.state.ConfigByID(req.ConfigID)
	if entry == nil {
		writeIssueError(w, http.StatusNotFound, "config_not_found",
			"this issuer does not know about that configId")
		return
	}
	attestationPolicy := entry.AttestationPolicy
	configJson := entry.Config
	baseTtl := resolveConfigTtl(entry)
	if arm, hasArm := attestationPolicy.armFor(req.Attestation.Platform); hasArm &&
		arm.Verifier == "android-key-attestation" && attestationPolicy.Mode == AttestationModeStrict {
		if req.V < 2 || req.Attestation.BoundDevicePk != req.DevicePk || req.Attestation.Proof == "" {
			writeIssueError(w, http.StatusUnauthorized, "attestation_failed", "Android attestation is not bound to this request key")
			return
		}
		if !s.attestationChallenges.Valid(req.Attestation.Nonce, time.Now()) {
			writeIssueError(w, http.StatusUnauthorized, "attestation_failed", "Android attestation challenge is stale or unknown")
			return
		}
	}

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

	// Which verifier applies depends on the requester's platform, so the
	// policy evaluator resolves it. A policy naming a verifier the registry
	// can't resolve is a misconfiguration, not a client error.
	decision, err := evaluateAttestationPolicy(
		attestationPolicy,
		req.Attestation,
		s.state.verifierRegistry.Lookup,
		baseTtl,
	)
	if err != nil {
		writeIssueError(w, http.StatusInternalServerError, "server_error",
			"resolve verifier: "+err.Error())
		return
	}
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

	expiresAt := time.Now().UTC().Add(decision.ttl).Format(time.RFC3339)

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

func writeIssueError(w http.ResponseWriter, status int, code, detail string) {
	writeJSON(w, status, IssueError{Error: code, Detail: detail})
}

// shortBase64 abbreviates a long identifier for logs, keeping the head and tail.
func shortBase64(s string) string {
	if len(s) <= 12 {
		return s
	}
	return s[:8] + "…" + s[len(s)-4:]
}

// writeJSON writes v as a JSON response with the given status. A write error
// after the header is committed is unrecoverable and intentionally dropped.
func writeJSON(w http.ResponseWriter, status int, v any) {
	buf, err := json.Marshal(v)
	if err != nil {
		http.Error(w, "encode: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if _, err := w.Write(buf); err != nil && !errors.Is(err, io.ErrClosedPipe) {

	}
}
