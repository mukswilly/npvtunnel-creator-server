package main

// Wire types for the JSON HTTP API. Field names and shapes here are part of the
// protocol contract: recipients and requesters depend on them byte-for-byte.

// AttestationBlob carries an optional device-attestation token alongside an
// issue request. It is always present in the request (even when empty) because
// Token is folded into the request signature; see verifyIssueRequestSignature.
type AttestationBlob struct {
	Platform string `json:"platform"`
	Token    string `json:"token"`
	Nonce    string `json:"nonce"`
}

// IssueRequest is the body of POST /v1/issue: a device asking this issuer to
// hand back the config registered under ConfigID. RequestSignature is an
// ECDSA-P256 signature, made by the DevicePk key, over a fixed string built
// from the other fields (see issueRequestSigningInput).
type IssueRequest struct {
	V                int             `json:"v"`
	DevicePk         string          `json:"devicePk"`
	Attestation      AttestationBlob `json:"attestation"`
	ConfigID         string          `json:"configId"`
	RequestNonce     string          `json:"requestNonce"`
	RequestSignature string          `json:"requestSignature"`
}

// IssueResponse is the success body of POST /v1/issue. ConfigB64 is the
// base64url config payload; ReceiptSig is the creator key's signature over the
// receipt input, letting the requester confirm the response came from this
// issuer and matches its nonce.
type IssueResponse struct {
	ConfigB64 string `json:"configB64"`

	ExpiresAt string `json:"expiresAt"`

	ReceiptSig string `json:"receiptSig"`
}

// IssueError is the error body for /v1/issue. Error is a stable machine code;
// RetryAfter is seconds, set on rate-limit responses.
type IssueError struct {
	Error      string `json:"error"`
	Detail     string `json:"detail,omitempty"`
	RetryAfter int    `json:"retryAfter,omitempty"`
}

// RedeemRequest is the body of POST /v1/redeem: a share-link token plus the
// recipient's P-256 compressed public key, to which the issued envelope's DEK
// is wrapped.
type RedeemRequest struct {
	V               int    `json:"v"`
	Token           string `json:"token"`
	RecipientPubkey string `json:"recipientPubkey"`
}

// RedeemError is the error body for /v1/redeem.
type RedeemError struct {
	Error      string `json:"error"`
	Detail     string `json:"detail,omitempty"`
	RetryAfter int    `json:"retryAfter,omitempty"`
}
