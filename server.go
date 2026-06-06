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
}

func NewServer(state *State, logger *slog.Logger) *Server {
	return &Server{state: state, logger: logger}
}

// Router returns the http.Handler for the public endpoints.
func (s *Server) Router() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/issue", s.handleIssue)
	mux.HandleFunc("POST /v1/redeem", s.handleRedeem)
	mux.HandleFunc("GET /v1/creator-pubkey", s.handleCreatorPubKey)
	mux.HandleFunc("GET /healthz", s.handleHealth)
	return mux
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
//  5. Compute the HMAC-bound credential bytes, encode per
//     ConfigEntry.CredentialEncoding, and substitute every occurrence of
//     credentialSentinel in the ConfigBody with the encoded form.
//  6. base64url-no-pad the substituted ConfigBody → ConfigB64.
//  7. Sign the receipt (covers devicePk, requestNonce, expiresAt, ConfigB64).
//  8. Emit the audit record and return 200 with IssueResponse.
func (s *Server) handleIssue(w http.ResponseWriter, r *http.Request) {
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
	// RECEIPT to this specific request for the legitimate client (see
	// issueReceiptSigningInput) — it is not a server-side anti-replay
	// store. This is acceptable because a replayed request only ever
	// yields a credential HMAC-bound to req.DevicePk: a replayer who
	// isn't that device can't use it on the VPN data plane (which
	// re-derives the HMAC over the connecting device's key), and volume
	// is capped by the per-(device,config) rate limit below. Genuine
	// request-replay resistance would need a signed issuedAt + acceptance
	// window — a breaking wire change requiring a coordinated client
	// rollout, deliberately not done here.

	// Look up the registered config. If a config registry is loaded but the
	// requested fp is not in it, return 404. If no registry is loaded
	// (configs.json absent / ephemeral mode), fall back to a stub
	// ConfigBody so the wire-protocol harness keeps working without a
	// registry.
	var configJson json.RawMessage
	var credentialEncoding string
	var attestationPolicy *AttestationPolicy
	// Baseline credential lifetime. Per-config override from the entry
	// (resolveCredTtl) when a registry is loaded; defaultCredTtl in the
	// no-registry stub path below.
	baseTtl := defaultCredTtl
	if s.state.HasConfigRegistry() {
		entry := s.state.ConfigByID(req.ConfigID)
		if entry == nil {
			writeIssueError(w, http.StatusNotFound, "config_not_found",
				"this issuer does not know about that configId")
			return
		}
		attestationPolicy = entry.AttestationPolicy

		// Per-(device, config) rate limit. Different configs have
		// independent quotas; a malicious device can't dodge the limit
		// by spreading requests across configs of the same creator
		// because the key includes configId. Limit value comes from
		// the policy (or its default).
		limit := resolveIssuanceLimit(attestationPolicy)
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

		configJson = entry.Config
		credentialEncoding = entry.CredentialEncoding
		baseTtl = resolveCredTtl(entry)
	} else {
		// Stub ConfigBody for ephemeral / no-registry mode. Carries no
		// credential — the wire-protocol harness checks shape + signing,
		// not the contents.
		configJson = json.RawMessage(
			`{"name":"stub","address":"stub.creator-server.example:443","type":"V2RAY","v2rayProfile":{"server":"stub.creator-server.example","serverPort":"443"}}`)
	}

	// Apply the creator's attestation policy. Modes: strict rejects
	// unattested; soft shortens TTL; observe logs only; off is a no-op.
	// When the policy names a Verifier, its Verdict
	// supersedes the 3.4b claimed-only check.
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
	// baseline (resolveCredTtl) in most modes; shorter under "soft" +
	// unattested.
	expiresAt := time.Now().UTC().Add(decision.ttl).Format(time.RFC3339)

	// Derive the HMAC-bound credential bytes, encode per the entry's
	// CredentialEncoding, and substitute into the merged ConfigBody
	// template. Same HMAC construction the VPN data plane re-runs to
	// validate the connecting client — different encoding per protocol.
	//
	// Skip substitution when no registry is loaded (the stub path has no
	// sentinel anyway, so a no-op walk would be wasted work).
	if s.state.HasConfigRegistry() {
		hmacBytes := deriveCredentialBytes(s.state.VpnHmacKey, req.DevicePk, expiresAt)
		encoded, encErr := encodeCredential(credentialEncoding, hmacBytes)
		if encErr != nil {
			writeIssueError(w, http.StatusInternalServerError, "server_error",
				"encode credential: "+encErr.Error())
			return
		}
		substituted, subErr := injectCredential(configJson, encoded)
		if subErr != nil {
			writeIssueError(w, http.StatusInternalServerError, "server_error",
				"inject credential: "+subErr.Error())
			return
		}
		configJson = substituted
	}

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
