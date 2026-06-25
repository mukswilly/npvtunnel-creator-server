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

// redeemConfig holds knobs for /v1/redeem. Centralized here so tests
// can override the defaults without poking at internals.
//
// Per-IP rate limit specifically defends against an attacker hammering
// the public endpoint to (a) exhaust legitimate tokens or (b) brute-
// force token-space discovery. The per-token redemption cap is the
// primary defense; this is the secondary one.
const (
	// redeemMaxPerIPPerHour bounds how many /v1/redeem calls one IP
	// can make in a sliding 1h window. Picked generous enough that a
	// recipient on a flaky network retrying a failed redemption won't
	// hit it; tight enough that brute-force exploration of token
	// space is impractical.
	redeemMaxPerIPPerHour = 30
)

// handleRedeem implements POST /v1/redeem.
//
// Flow:
//
//  1. Parse + validate the request shape.
//  2. Per-IP rate-limit check (before any state mutation so a brute-
//     force can't exhaust tokens by walking the space).
//  3. Look up the token (read-only): is it registered + still valid?
//  4. Decode the recipient pubkey to make sure it's a well-formed
//     P-256 compressed point. We don't sign anything with it; we just
//     refuse junk inputs early.
//  5. Mint the V2 envelope addressed to that pubkey. configId comes
//     from the token entry — reusing it across redemptions of the
//     same token preserves "this is the same logical config" on the
//     recipient side.
//  6. Atomically decrement RemainingRedemptions + persist.
//  7. Return raw envelope bytes (octet-stream); recipient feeds them
//     straight into the existing import flow.
//
// What this handler is NOT:
//   - Not signed by the requester. The token is the bearer token.
//     Anyone with the URL can redeem; the per-token redemption count +
//     the per-IP rate limit are the only gates.
//   - Not idempotent. A successful redemption uses up one of the
//     token's redemption slots. A network retry where the response
//     was lost means the recipient burned a slot they don't have a
//     receipt for — that's by design (idempotency keys would let an
//     attacker replay-and-confuse).
//   - Not how /v1/issue works. /v1/redeem hands out *discovery
//     envelopes* (which point at the issuer URL). /v1/issue returns the
//     per-config payload with a signed receipt — a completely separate
//     code path, called much more often, with its own rate limiting.
func (s *Server) handleRedeem(w http.ResponseWriter, r *http.Request) {
	// Hot-reload redemption-tokens.json if a separate mint-share-link /
	// revoke-token subprocess has bumped it since our last load. Cheap
	// when nothing changed (one os.Stat); closes the "operator runs
	// mint-share-link, recipient gets 404 until systemctl restart"
	// papercut.
	if err := s.state.ReloadRedemptionTokensIfChanged(); err != nil {
		s.logger.Warn("redemption-tokens reload failed", "err", err.Error())
		// Keep going — last good in-memory state is still useable.
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

	// Per-IP rate limit before any state read. Brute-forcing through
	// token-space costs an attacker more network round-trips than
	// they have budget for under this limit.
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

	// Decode recipient pubkey early. Refusing malformed pubkeys
	// before token consumption means an attacker can't poison-pill a
	// token slot with garbage.
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

	// Token must exist and be valid.
	token := s.state.LookupRedemptionToken(req.Token)
	if token == nil {
		writeRedeemError(w, http.StatusNotFound, "token_not_found",
			"no redemption token registered with this id")
		return
	}

	// Cheap pre-mint validity gate. ConsumeRedemptionToken below is the
	// authoritative atomic check (it re-runs these under the write lock
	// so a race can't overdraw the last slot), but doing the obvious
	// rejections HERE — before the expensive mintIssuerEnvelope — closes
	// a CPU-amplification vector: tokens are mass-shared to public
	// channels by design, so every adversary already holds valid token
	// strings. Without this gate, replaying /v1/redeem against an
	// exhausted or expired (but still-registered) public token forces a
	// full asymmetric-crypto mint per request that's then discarded at
	// the consume step. Reject exhausted/expired tokens up front so the
	// wasted-work path costs an attacker no server CPU.
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

	// Require the operator to have set the public issuer URL —
	// without it, the minted envelope's IssuerBody.issuerUrl would
	// be empty and recipients couldn't fetch configs.
	if s.state.PublicIssuerURL == "" {
		writeRedeemError(w, http.StatusInternalServerError, "server_error",
			"this server is not configured to mint redemptions (PublicIssuerURL not set)")
		return
	}

	// Look up the named configId in configs.json. We could let the
	// minter succeed and the recipient discover this on first
	// /v1/issue, but doing the check here gives the operator a clean
	// error path: if they accidentally revoked a config that still
	// has live tokens pointing at it, the failure surface is the
	// share link, not every individual recipient's connect.
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

	// Decode the persisted configId. Should be base64url of 16 bytes
	// (mint-share-link enforces this at creation time); a malformed
	// value here is operator state corruption.
	configID, err := b64url.DecodeString(token.ConfigID)
	if err != nil || len(configID) != envelopeConfigIDLen {
		writeRedeemError(w, http.StatusInternalServerError, "server_error",
			"token has malformed configId")
		return
	}

	// Mint the envelope BEFORE consuming the redemption slot. A mint
	// failure shouldn't burn a slot. The handful of failure modes
	// here (recipient pubkey not on the P-256 curve, signing key
	// glitch) are bad-input or server-state errors, not "natural"
	// rejections.
	mintRes, err := mintIssuerEnvelope(mintInput{
		CreatorKey:       s.state.CreatorSigningKey,
		RecipientPubKeys: [][]byte{recipientPub},
		IssuerURL:        s.state.PublicIssuerURL,
		ConfigID:         configID,
		// Carry the creator's use restrictions (mobile-only / expiry / messages)
		// into the envelope so share-link recipients enforce them like a file
		// recipient. attestationLevel stays NONE (the client can't verify it);
		// device attestation is gated separately by the runtime AttestationPolicy
		// on the configs.json entry at /v1/issue.
		Policy: cfgEntry.IssuedPolicy,
	})
	if err != nil {
		writeRedeemError(w, http.StatusBadRequest, "bad_pubkey",
			"mint failed: "+err.Error())
		return
	}

	// Now claim the slot. Re-checks the same conditions LookupRedemptionToken
	// passed, under the write lock, so two concurrent redemptions
	// can't both succeed on the last available slot.
	result := s.state.ConsumeRedemptionToken(req.Token, time.Now().UTC())
	if !result.Consumed {
		// Map the internal reason to HTTP status.
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
		// Client disconnected mid-response. The slot stays consumed
		// — same trade-off as `not idempotent` documented above.
		_ = err
	}
}

// redeemReasonDetail maps the internal Reason string to a recipient-
// facing message. Kept brief so the app can surface them to the user
// without further translation.
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

// clientIP returns the source address used as the per-IP rate-limit key.
//
// SECURITY: X-Forwarded-For is client-settable, so it is honored ONLY
// when the immediate peer (RemoteAddr) is one of the operator-declared
// trusted proxies (-trusted-proxy CIDRs). A direct-internet deployment
// passes no trusted proxies, so XFF is ignored entirely and the raw
// RemoteAddr is used — a client connecting directly cannot spoof the
// header to dodge the rate limit. (The earlier version trusted XFF
// unconditionally, which made the /v1/redeem per-IP limit bypassable by
// any client that simply set the header.)
//
// When the peer IS trusted, we walk XFF right-to-left and return the
// first hop that is not itself a trusted proxy — that's the closest
// address our trusted edge couldn't vouch for, i.e. the real client as
// the edge saw it. A trusted proxy that overwrites XFF (Caddy's
// reverse_proxy default) leaves a single entry, which this returns.
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
	// Every hop was a trusted proxy (unusual). Fall back to the peer.
	return host
}

// ipInAny reports whether ipStr parses to an IP contained in any of the
// given CIDRs.
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
