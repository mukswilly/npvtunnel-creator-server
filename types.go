package main

// JSON shapes for the issuance + redemption protocol messages. Adding a
// field is non-breaking; renaming or removing requires a protocol-version
// bump.

// ──────────────────────────────────────────────────────────────────
// Issuance — POST /v1/issue
// ──────────────────────────────────────────────────────────────────

// AttestationBlob is the optional attestation evidence carried in an
// issue request. Its token is part of the request signing input;
// verification of the token's contents is optional (governed by the
// attestation policy).
type AttestationBlob struct {
	Platform string `json:"platform"` // "ANDROID" | "IOS" | "NONE"
	Token    string `json:"token"`
	Nonce    string `json:"nonce"`
}

// IssueRequest is the body of POST /v1/issue.
//
// ConfigID is the routing key — base64url-no-pad of 16 bytes, read by the
// recipient from the envelope header at import time. Replaces the older
// SHA-256(envelopeBytes) "configFp" scheme which couldn't survive the
// redemption flow (each redemption mints a fresh envelope with a
// different hash; configId is stable by construction). See the
// ConfigEntry doc comment in state.go.
type IssueRequest struct {
	V                int             `json:"v"`
	DevicePk         string          `json:"devicePk"`
	Attestation      AttestationBlob `json:"attestation"`
	ConfigID         string          `json:"configId"`
	RequestNonce     string          `json:"requestNonce"`
	RequestSignature string          `json:"requestSignature"`
}

// IssueResponse is the success body of POST /v1/issue.
//
// The wire shape collapses to a single ConfigBody payload (base64url-no-
// pad of its JSON), returned verbatim from the routed configs.json entry.
// The already-working config lives inside that payload at whichever
// slot the operator's config put it — typically v2rayProfile.password or
// sshConfig.sshPassword. The issuer does not control the data-plane
// server, so it neither mints nor mutates the config.
type IssueResponse struct {
	// ConfigB64 is base64url-no-pad of a ConfigBody JSON. The recipient
	// decodes and parses it through the same path V1 envelope bodies use,
	// so every protocol the V1 path supports automatically works here.
	ConfigB64 string `json:"configB64"`
	// ExpiresAt is the RFC3339 UTC timestamp at which the recipient should
	// re-fetch. Since the issuer doesn't run the data plane this is a
	// client re-fetch cadence, not a server-side config expiry.
	ExpiresAt string `json:"expiresAt"`
	// ReceiptSig is ECDSA-P256 P1363, base64url-no-pad. Covers
	// "v1.receipt|" + devicePk + "|" + requestNonce + "|" + expiresAt + "|" + configB64.
	// The recipient verifies this against the creator pubkey pinned in
	// the discovery envelope BEFORE consuming ConfigB64.
	ReceiptSig string `json:"receiptSig"`
}

// IssueError is the failure body of POST /v1/issue.
type IssueError struct {
	Error      string `json:"error"`
	Detail     string `json:"detail,omitempty"`
	RetryAfter int    `json:"retryAfter,omitempty"`
}

// ──────────────────────────────────────────────────────────────────
// Share-link redemption (POST /v1/redeem)
//
// A creator mints a redemption token via the `mint-share-link`
// subcommand, posts `npvtunnel://join?u=<base64url(/v1/redeem URL)>&t=<token>`
// publicly. Recipients tap the link; their app POSTs RedeemRequest;
// the server validates the token, decrements its remaining count,
// mints a V2 issuer envelope addressed to RecipientPubkey, and
// returns the raw envelope bytes.
//
// The share-link flow: one tap from a public channel to a fully-
// installed, per-recipient sealed config, with real cryptographic
// confidentiality and device-bound short-TTL configs.
// ──────────────────────────────────────────────────────────────────

// RedeemRequest is the JSON body the recipient POSTs to /v1/redeem.
// No signature: the token is the bearer token. RecipientPubkey is
// what the envelope ends up sealed to, so an attacker swapping it
// can't decrypt the result.
type RedeemRequest struct {
	V               int    `json:"v"`
	Token           string `json:"token"`
	RecipientPubkey string `json:"recipientPubkey"`
}

// RedeemError is the failure body of POST /v1/redeem. Same shape as
// IssueError so a recipient's error decoders can reuse most of the
// machinery. Status code carries the coarse classification.
type RedeemError struct {
	// One of:
	//   token_not_found       — 404
	//   token_exhausted       — 410 (remainingRedemptions hit 0)
	//   token_expired         — 410 (past expiresAt)
	//   bad_pubkey            — 400 (malformed base64 or wrong length)
	//   bad_request           — 400 (missing field, bad version)
	//   rate_limited          — 429
	//   server_error          — 500
	Error      string `json:"error"`
	Detail     string `json:"detail,omitempty"`
	RetryAfter int    `json:"retryAfter,omitempty"`
}
