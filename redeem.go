package main

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// redeemMaxPerIPPerHour caps share-link redemptions per client IP per hour.
const (
	redeemMaxPerIPPerHour = 30
)

// handleRedeem serves POST /v1/redeem: it exchanges a valid, unexhausted
// share-link token plus a recipient public key for a freshly minted envelope
// wrapped to that recipient. The token's config is looked up in the registry,
// an envelope is minted under this server's PublicIssuerURL, and the token is
// consumed (decremented) only after a successful mint. The response body is the
// raw .npvs bytes.
func (s *Server) handleRedeem(w http.ResponseWriter, r *http.Request) {

	if err := s.state.ReloadRedemptionTokensIfChanged(); err != nil {
		s.logger.Warn("redemption-tokens reload failed", "err", err.Error())

	}
	if err := s.state.ReloadConfigsIfChanged(); err != nil {
		s.logger.Warn("configs.json reload failed", "err", err.Error())
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 32*1024))
	if err != nil {
		writeRedeemError(w, http.StatusBadRequest, "bad_request", "read body: "+err.Error())
		return
	}
	var req RedeemRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeRedeemError(w, http.StatusBadRequest, "bad_request", "parse json: "+err.Error())
		return
	}
	if req.V != 1 {
		writeRedeemError(w, http.StatusBadRequest, "bad_request", "unsupported version")
		return
	}
	if req.Token == "" || req.RecipientPubkey == "" {
		writeRedeemError(w, http.StatusBadRequest, "bad_request", "missing required field")
		return
	}

	ip := clientIP(r, s.state.TrustedProxies)
	decision := s.state.redemptionLimiter.Allow(ip, redeemMaxPerIPPerHour, 1*time.Hour)
	if !decision.Allowed {
		retryAfterSec := int(decision.RetryAfter.Seconds() + 0.5)
		if retryAfterSec < 1 {
			retryAfterSec = 1
		}
		w.Header().Set("Retry-After", strconv.Itoa(retryAfterSec))
		writeJSON(w, http.StatusTooManyRequests, RedeemError{
			Error:      "rate_limited",
			Detail:     "redemption rate limit exceeded for this client",
			RetryAfter: retryAfterSec,
		})
		return
	}

	recipientPub, err := b64url.DecodeString(req.RecipientPubkey)
	if err != nil {
		writeRedeemError(w, http.StatusBadRequest, "bad_pubkey", "recipientPubkey base64 decode: "+err.Error())
		return
	}
	if len(recipientPub) != envelopeP256CompLen {
		writeRedeemError(w, http.StatusBadRequest, "bad_pubkey",
			"recipientPubkey must be 33 bytes (P-256 compressed)")
		return
	}

	token := s.state.LookupRedemptionToken(req.Token)
	if token == nil {
		writeRedeemError(w, http.StatusNotFound, "token_not_found",
			"no redemption token registered with this id")
		return
	}

	if token.RemainingRedemptions <= 0 {
		writeRedeemError(w, http.StatusGone, "token_exhausted",
			redeemReasonDetail("token_exhausted"))
		return
	}
	if token.ExpiresAt != "" {
		if expires, perr := time.Parse(time.RFC3339, token.ExpiresAt); perr == nil &&
			time.Now().UTC().After(expires) {
			writeRedeemError(w, http.StatusGone, "token_expired",
				redeemReasonDetail("token_expired"))
			return
		}
	}

	if s.state.PublicIssuerURL == "" {
		writeRedeemError(w, http.StatusInternalServerError, "server_error",
			"this server is not configured to mint redemptions (PublicIssuerURL not set)")
		return
	}

	if !s.state.HasConfigRegistry() {
		writeRedeemError(w, http.StatusInternalServerError, "server_error",
			"no config registry loaded; tokens cannot be honored")
		return
	}
	cfgEntry := s.state.ConfigByID(token.ConfigID)
	if cfgEntry == nil {
		writeRedeemError(w, http.StatusInternalServerError, "server_error",
			"token references a configId that's no longer registered")
		return
	}

	configID, err := b64url.DecodeString(token.ConfigID)
	if err != nil || len(configID) != envelopeConfigIDLen {
		writeRedeemError(w, http.StatusInternalServerError, "server_error",
			"token has malformed configId")
		return
	}

	mintRes, err := mintIssuerEnvelope(mintInput{
		CreatorKey:       s.state.CreatorSigningKey,
		RecipientPubKeys: [][]byte{recipientPub},
		IssuerURL:        s.state.PublicIssuerURL,
		ConfigID:         configID,

		Policy: cfgEntry.IssuedPolicy,
	})
	if err != nil {
		writeRedeemError(w, http.StatusBadRequest, "bad_pubkey",
			"mint failed: "+err.Error())
		return
	}

	// Decrement only now that the envelope minted successfully, so a failed
	// mint never burns a redemption.
	result := s.state.ConsumeRedemptionToken(req.Token, time.Now().UTC())
	if !result.Consumed {

		status := http.StatusGone
		switch result.Reason {
		case "token_not_found":
			status = http.StatusNotFound
		}
		writeRedeemError(w, status, result.Reason, redeemReasonDetail(result.Reason))
		return
	}

	auditEmit(s.logger, s.state.AuditSalt,
		"redeem.granted",
		req.RecipientPubkey,
		shortBase64(token.ConfigID),
		"", "NONE", false, 0,
		"token", shortBase64(req.Token),
		"label", token.Label,
		"remainingAfter", token.RemainingRedemptions-1,
	)

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="share.npvs"`)
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(mintRes.EnvelopeBytes); err != nil {

		_ = err
	}
}

// redeemReasonDetail maps a machine reason code to a recipient-facing message.
func redeemReasonDetail(reason string) string {
	switch reason {
	case "token_not_found":
		return "this share link is no longer recognized"
	case "token_exhausted":
		return "this share link has been used up"
	case "token_expired":
		return "this share link has expired"
	default:
		return ""
	}
}

func writeRedeemError(w http.ResponseWriter, status int, code, detail string) {
	writeJSON(w, status, RedeemError{Error: code, Detail: detail})
}

// clientIP resolves the rate-limit key for a request. X-Forwarded-For is honored
// only when the immediate peer is a trusted proxy; it then walks the header from
// right to left and returns the first address that is not itself trusted (the
// real client). With no trusted proxies it always uses the socket peer, so
// clients cannot spoof their key.
func clientIP(r *http.Request, trusted []*net.IPNet) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}

	xff := r.Header.Get("X-Forwarded-For")
	if xff == "" || len(trusted) == 0 || !ipInAny(host, trusted) {
		return host
	}

	parts := strings.Split(xff, ",")
	for i := len(parts) - 1; i >= 0; i-- {
		ip := strings.TrimSpace(parts[i])
		if ip == "" {
			continue
		}
		if !ipInAny(ip, trusted) {
			return ip
		}
	}

	return host
}

// ipInAny reports whether ipStr falls within any of the given networks.
func ipInAny(ipStr string, nets []*net.IPNet) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}
