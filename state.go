package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// ConfigEntry is one VPN config a creator's issuer knows how to mint
// session credentials for. Recipients refer to a config by its
// `configId` — the 16-byte stable identifier embedded in the envelope
// header, base64url-no-pad encoded.
//
// # Why configId, not SHA-256(envelope)
//
// Earlier iterations routed by `configFp = base64url(SHA-256(envelope
// bytes))`. That works for named-recipient envelopes where one envelope
// is shared by N recipients (everyone computes the same hash). It
// breaks when the share-link redemption flow mints a fresh envelope
// per recipient — each recipient computes a different hash, the
// configs.json entry's single fingerprint matches none of them, and
// every recipient's connect attempt 404s.
//
// configId is operator-generated, stored in the token at mint-share-
// link time, embedded verbatim in every envelope minted for that
// token, and the recipient reads it back from the envelope header.
// Same value for every recipient of the same logical config; routing
// works.
//
// Lives in state-dir/configs.json. configs.json reload requires a
// restart; redemption-tokens.json hot-reloads on mtime change.
//
// # The Config field
//
// Config carries a full ConfigBody template — same JSON shape the V1
// envelope body uses (see the client). Wherever the operator
// wants the per-session credential to land, they place the literal string
// [credentialSentinel] ("$NPVT_CREDENTIAL$"). At /v1/issue time, after
// merging in any recipient variant, the server replaces every occurrence
// of that sentinel with the HMAC-derived credential, encoded per
// CredentialEncoding. The substituted ConfigBody is base64url-no-pad
// encoded into IssueResponse.ConfigB64 — the recipient parses it as a
// ConfigBody and uses it directly through the normal connect path.
//
// What this buys: every VPN protocol the recipient app's v2ray /
// SSH config types support works end-to-end with zero extra client
// code. Adding a new protocol is one configs.json entry, not a server +
// client deployment.
type ConfigEntry struct {
	// ConfigID is the routing key — must match IssueRequest.ConfigID
	// and the `configId` field in every envelope minted for this config.
	// base64url-no-pad of 16 raw bytes.
	ConfigID string `json:"configId"`

	// VpnProtocol is informational only — surfaces in audit logs and is
	// echoed into the discovery envelope's vpnProtocolHint when an
	// operator runs `creator-server mint`. NOT load-bearing for the
	// issuance pipeline (Config carries everything the recipient needs).
	VpnProtocol string `json:"vpnProtocol,omitempty"`

	// CredentialEncoding names how the HMAC-bound credential bytes get
	// rendered when substituted into Config's sentinel slot. See
	// inject.go for the recognized values. Empty defaults to
	// "base64url-raw" — works for any opaque-string credential slot
	// (e.g. SSH password). VLESS/VMess UUID slots require "uuid-v4".
	CredentialEncoding string `json:"credentialEncoding,omitempty"`

	// Config is the full ConfigBody JSON the issuer ships to recipients
	// (after per-recipient variant merge + credential substitution).
	// Shape mirrors the ConfigBody JSON the client expects:
	//
	//   { "name": "...", "address": "host:port",
	//     "type": "V2RAY" | "SSH",
	//     "v2rayProfile": { ... } | null,
	//     "sshConfig":    { ... } | null }
	//
	// Secret fields (v2rayProfile.password, sshConfig.sshPassword, etc.)
	// should be set to [credentialSentinel]; the server substitutes the
	// HMAC-derived credential at mint time.
	//
	// Required when this entry is registered for routing — load-time
	// validation rejects entries with no Config.
	Config json.RawMessage `json:"config"`

	// RecipientVariants lets a creator hand DIFFERENT config templates to
	// different recipients of the same configId, so a leaked connection
	// config can be traced back to the recipient who published it. Keys are the
	// recipient's devicePk (base64url-no-pad, 33 bytes pre-encoding —
	// same form as IssueRequest.DevicePk). Values are partial ConfigBody
	// objects: any field present in the variant overrides the
	// corresponding field in the base Config via deep merge (object-
	// valued fields recurse; scalar/array values replace).
	//
	// Typical use for xray-vless-reality: a creator pre-configures their
	// VPN server with several acceptable shortIds (one per recipient) and
	// puts them in the variants here:
	//
	//   "recipientVariants": {
	//     "<bobDevicePk>":   { "v2rayProfile": { "shortId": "7b2c..." } },
	//     "<carolDevicePk>": { "v2rayProfile": { "shortId": "9d41..." } }
	//   }
	//
	// When a leaked connection config (e.g. its v2rayProfile.shortId)
	// surfaces publicly, the shortId tells the creator which recipient to revoke.
	//
	// Caveats worth knowing:
	//   - Sophisticated leakers can strip the watermark before publishing
	//     (randomize shortId, blank path). This is attribution against
	//     careless leakers — the realistic threat for a typical
	//     audience — not against motivated adversaries.
	RecipientVariants map[string]json.RawMessage `json:"recipientVariants,omitempty"`

	// AttestationPolicy controls how /v1/issue treats attestation evidence
	// from the recipient app. Absent (nil) is equivalent to mode = "off"
	// and is the back-compat default — existing configs.json without this
	// field keeps working unchanged.
	AttestationPolicy *AttestationPolicy `json:"attestationPolicy,omitempty"`
}

// defaultMaxIssuancesPerHour is the sliding-window rate limit applied
// when a policy is configured (mode != off) but doesn't override the
// limit explicitly. Picks a value generous enough that a legitimate
// recipient on a flaky network reconnecting often won't hit it, tight
// enough that a malicious recipient pulling fresh creds in a loop will.
//
// Sensible upper bound for "how often does a real user reconnect in an
// hour?": <= 5 in pathological cases (flaky network, app backgrounding,
// VPN service restarts). The limit at 10 leaves margin.
const defaultMaxIssuancesPerHour = 10

// AttestationPolicy is the creator-side risk-tier knob for issuance.
//
// What each mode actually does TODAY:
//
//   off      Ignore attestation entirely. Default when AttestationPolicy is nil.
//   observe  Log what the client claimed (platform, token presence), never block.
//            Useful as a learn-the-audience phase before turning on enforcement.
//   soft     Accept all requests, but shorten TTL for clients that don't claim
//            attestation (platform == NONE). The soft-failure TTL is set by
//            SoftFailureTtlSec or 300s (5 min) by default. Lets a creator
//            allow sideloaded / no-Play-Services users to connect with bounded
//            blast radius if their device is later identified as compromised.
//   strict   Reject (401 attestation_failed) any request that doesn't claim
//            attestation. Locks out clients on devices that can't produce a
//            Play Integrity / App Attest token. Not appropriate for sideload-
//            heavy audiences.
//
// What this does NOT yet do:
//
// The issuer currently checks whether the client *claimed* attestation
// (Attestation.Platform != "NONE"). It does NOT verify the token by calling
// Google Play Integrity API / Apple App Attest. A malicious client can
// claim ANDROID + send junk and get through soft/observe modes. That's
// honest — until verdict verification lands, "platform claim" is the
// strongest signal available, and "strict" still keeps out clients that
// can't even bother to mint a stub token.
type AttestationPolicy struct {
	// Mode is one of: "off", "observe", "soft", "strict".
	Mode string `json:"mode"`

	// SoftFailureTtlSec — credential TTL in seconds when the policy is
	// "soft" and the request didn't claim attestation. Ignored under
	// other modes. Zero means use the default (300 = 5 minutes).
	SoftFailureTtlSec int `json:"softFailureTtlSec,omitempty"`

	// MaxIssuancesPerHour caps how many credentials one devicePk may
	// receive in a sliding 1-hour window. Defends against credential-
	// draining abuse (a compromised recipient pulling many creds in a
	// loop) without requiring per-creator infrastructure.
	//
	//   <= 0 : unlimited (no rate limit applied).
	//   > 0  : that many requests per hour per device.
	//   absent + mode != off : use defaultMaxIssuancesPerHour (10).
	//   absent + mode == off OR policy absent entirely : unlimited
	//     (preserves 3.1a back-compat for deployments that haven't
	//     configured any policy).
	MaxIssuancesPerHour int `json:"maxIssuancesPerHour,omitempty"`

	// Verifier names which AttestationVerifier implementation to run
	// against the client's attestation token. Empty (default) skips
	// verification — the policy modes still gate on "claimed" vs
	// "not claimed" exactly as in 3.4b.
	//
	// Recognized values (3.4e-i):
	//   "android-key-attestation" — structural verification only.
	//                               Chain-to-Google not yet verified
	//                              . See verifier.go.
	//
	// Unknown values fail at startup with the list of recognized names.
	Verifier string `json:"verifier,omitempty"`

	// RequireHardwareBacked, when true, additionally requires that the
	// verifier's Verdict reports a hardware-backed key (TEE or
	// StrongBox). Software-only keys are rejected.
	//
	// Only meaningful when Verifier is set. With Verifier empty, this
	// field is ignored (there's no verdict to inspect).
	//
	// Honest framing: HardwareBacked is derived from the
	// attestationSecurityLevel field of the leaf cert's attestation
	// extension. A self-signed cert with the right ASN.1 can claim
	// "StrongBox" and pass this gate alone. To require that the
	// hardware claim actually came from a Google-signed device, pair
	// this with RequireTrustedRoot.
	RequireHardwareBacked bool `json:"requireHardwareBacked,omitempty"`

	// RequireTrustedRoot, when true, additionally requires that the
	// verifier's Verdict reports a chain anchored at one of the
	// bundled Google AKA roots. Chains that don't terminate at a
	// known root are rejected even when they parse structurally and
	// claim StrongBox/TEE.
	//
	// This is the cryptographically-meaningful gate against self-
	// signed / emulated attestation. Recommended in combination with
	// RequireHardwareBacked on strict-mode configs.
	//
	// Default false for back-compat with deployments that adopted the
	// 3.4e-i verifier knob — those keep behaving as before until the
	// operator explicitly opts in.
	RequireTrustedRoot bool `json:"requireTrustedRoot,omitempty"`

	// RequireVerifiedBoot, when true, additionally requires that the
	// verifier's Verdict reports VerifiedBootState == "verified" AND
	// DeviceLocked == true. This is the AKA RootOfTrust gate
	//: a real hardware-backed key on a real device
	// running an unmodified OEM-signed OS image.
	//
	// What it blocks that the prior gates can't: a real-but-rooted
	// device — the chain anchors at Google's roots and the key is
	// hardware-backed, but the bootloader is unlocked. Combined with
	// RequireTrustedRoot + RequireHardwareBacked, this raises the
	// cost-per-leak from "any real phone" to "a clean OEM phone
	// running stock OS." Recommended for managed-audience strict-mode
	// configs.
	//
	// Default false for back-compat. Sideload-heavy creators should
	// leave this off — many users in censored regions run rooted
	// devices by necessity (alternative app stores, vendor
	// limitations). See principles.md §2.
	//
	// Apple App Attest does NOT carry a verified-boot signal in its
	// attestation object — iOS is closed enough that Apple's
	// position is "if the chain validates, the device is real." If
	// this field is true for a config whose verifier is "apple-app-
	// attest", the verifier surfaces an empty VerifiedBootState and
	// the gate will reject all iOS clients. Don't pair them.
	RequireVerifiedBoot bool `json:"requireVerifiedBoot,omitempty"`

	// AppID is the iOS application identifier ("TEAMID.bundle.id")
	// the App Attest verifier expects in the attestation's authData.
	// REQUIRED when Verifier == "apple-app-attest"; ignored otherwise.
	//
	// The verifier checks that authData.rpIdHash == SHA256(AppID),
	// which is how App Attest binds an attestation to a specific
	// app — without this check, an attacker could replay an
	// attestation produced by a different iOS app on the same
	// device.
	AppID string `json:"appId,omitempty"`
}

const (
	AttestationModeOff     = "off"
	AttestationModeObserve = "observe"
	AttestationModeSoft    = "soft"
	AttestationModeStrict  = "strict"

	// defaultSoftFailureTtlSec is the credential lifetime for soft-mode
	// requests with no claimed attestation. Short enough to bound damage
	// if the device turns out to be compromised, long enough that a flaky
	// network doesn't cause reconnect storms.
	defaultSoftFailureTtlSec = 300
)

func validAttestationMode(m string) bool {
	switch m {
	case AttestationModeOff, AttestationModeObserve, AttestationModeSoft, AttestationModeStrict:
		return true
	}
	return false
}

type State struct {
	mu sync.RWMutex

	// CreatorSigningKey signs Phase-3 issuance receipts. Persisted under
	// stateDir as creator-key.pem (PKCS#8 PEM). The matching public key is
	// exposed via GET /v1/creator-pubkey for testing — production
	// deployments pin it in the recipient's discovery envelope.
	CreatorSigningKey *ecdsa.PrivateKey

	// AuditSalt is a 32-byte random salt used to hash devicePks in audit
	// log records, so a leaked or shared audit log doesn't expose which
	// recipients are using the issuer. Persisted under stateDir as
	// audit-salt.bin (0600). Generated on first run.
	//
	// Honest framing of what this defends against:
	//   - Log file copied off-host (operator email, leaked backup, log
	//     aggregator with broader read access than the host): protected.
	//     The hash is unreversible without the salt.
	//   - Casual sysadmin browse of /var/log: protected.
	//   - Full VPS seizure: NOT protected — the salt is on the same disk
	//     as the audit log, so an attacker who has both can re-hash
	//     known devicePks to identify them in the log. Defending against
	//     this requires storing the salt off-VPS, which is operationally
	//     impractical for a single-binary deployment. Documented in
	//     README as a known limit.
	//
	// Hash format: `base64url-no-pad(SHA-256(AuditSalt || devicePkBytes))`.
	// devicePkBytes is the raw base64url-decoded pubkey, NOT the base64
	// string — keeps the input space tight.
	AuditSalt []byte

	// VpnHmacKey is a 32-byte secret shared between the issuer and the
	// VPN server. Persisted under stateDir as vpn-hmac-key.bin (0600).
	// Every issuance receipt's sessionCred is derived as:
	//   sessionCred = base64url(HMAC-SHA256(vpnHmacKey,
	//                            "v1.cred|"+devicePk+"|"+expiresAt))
	// so the VPN server can verify a recipient's claimed credential
	// without an online RPC to the issuer (it just re-runs the HMAC and
	// compares). A leaked sessionCred from one device can't be replayed
	// from a different device — the devicePk is part of the HMAC input,
	// and the VPN server checks the device that's actually connecting.
	//
	// Losing or rotating this key forces every active session to
	// reconnect. Treat the file like any other long-lived secret.
	VpnHmacKey []byte

	// stateDir is where persistent files (creator key, configs.json) live.
	// Empty in tests that don't need persistence.
	stateDir string

	// configs maps ConfigFp -> ConfigEntry. nil when no configs.json was
	// found at startup; /v1/issue falls back to the 3.1a stub response.
	configs map[string]*ConfigEntry

	// revocations maps devicePk -> RevocationEntry. Empty map when
	// revoked.json is absent. Lookup is O(1) and runs after request
	// signature verification, so we know the claimed devicePk is real
	// before checking it against the list.
	revocations map[string]*RevocationEntry

	// issuanceLimiter is the per-devicePk sliding-window rate limiter
	// for /v1/issue. Shared across all configFps so a malicious
	// device can't sidestep the cap by spreading requests across
	// multiple configs from the same creator.
	issuanceLimiter *rateLimiter

	// verifierRegistry maps the AttestationPolicy.Verifier name to a
	// verifier instance. Initialized at State construction with the
	// built-in verifiers.
	verifierRegistry *verifierRegistry

	// PublicIssuerURL is the externally-reachable URL of this server's
	// /v1/issue endpoint, set via the -public-issuer-url flag at
	// startup. Used by /v1/redeem when minting an envelope so the
	// envelope's IssuerBody.issuerUrl points back at this server.
	//
	// Empty means /v1/redeem is unavailable — startup logs a warning,
	// and POST /v1/redeem returns 500 server_error. /v1/issue is
	// unaffected (it doesn't need to know its own URL).
	PublicIssuerURL string

	// redemptionTokens maps Token (base64url string) to
	// *RedemptionToken. Loaded from redemption-tokens.json at startup;
	// persisted on every consume via write-then-rename. Hot-reloaded
	// from disk when the file's mtime changes (so `creator-server
	// mint-share-link` produces immediately-live tokens without needing
	// a server restart — see ReloadRedemptionTokensIfChanged).
	redemptionTokens map[string]*RedemptionToken

	// redemptionTokensPath is where redemptionTokens persists. Empty
	// in tests that use NewState() without a directory.
	redemptionTokensPath string

	// redemptionTokensMtime is the file mtime at last successful load.
	// Compared on each /v1/redeem; a newer mtime triggers a reload.
	// Zero value (epoch) means "never loaded from disk" — first call
	// will treat any file's mtime as newer and reload.
	redemptionTokensMtime time.Time

	// redemptionLimiter is the per-IP sliding-window rate limiter on
	// POST /v1/redeem. Independent of issuanceLimiter — the redemption
	// endpoint is public and unauthenticated (the token is the only
	// gate), so it needs its own brute-force defense. Limit lives in
	// redeemConfig below.
	redemptionLimiter *rateLimiter

	// TrustedProxies are the CIDRs of reverse proxies whose
	// X-Forwarded-For header clientIP is allowed to believe. Empty (the
	// default, and correct for a direct-internet TLS deployment) means
	// X-Forwarded-For is ignored entirely so a client can't spoof its
	// rate-limit key. Set via the -trusted-proxy flag at startup.
	TrustedProxies []*net.IPNet
}

// SweepRateLimiters evicts inactive entries from both rate-limiter maps.
// Called periodically from main()'s ticker so the maps don't grow
// without bound on a long-running process (each distinct devicePk or
// client IP otherwise leaves a permanent entry). window should match the
// limiter window (1h) so an entry is only dropped once it can no longer
// affect a decision.
func (s *State) SweepRateLimiters(window time.Duration) {
	s.issuanceLimiter.Sweep(window)
	s.redemptionLimiter.Sweep(window)
}

// NewState is the in-memory, no-persistence constructor. Generates a fresh
// creator key, vpn-hmac-key, and audit-salt each call; suitable for tests
// that don't span restart. Production code path calls NewStateWithDir.
func NewState() *State {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic("ecdsa.GenerateKey: " + err.Error())
	}
	hmacKey := make([]byte, 32)
	if _, err := rand.Read(hmacKey); err != nil {
		panic("rand.Read for hmac key: " + err.Error())
	}
	auditSalt := make([]byte, 32)
	if _, err := rand.Read(auditSalt); err != nil {
		panic("rand.Read for audit salt: " + err.Error())
	}
	return &State{
		CreatorSigningKey: priv,
		VpnHmacKey:        hmacKey,
		AuditSalt:         auditSalt,
		issuanceLimiter:   newRateLimiter(),
		verifierRegistry:  newVerifierRegistry(),
		redemptionTokens:  map[string]*RedemptionToken{},
		redemptionLimiter: newRateLimiter(),
	}
}

// NewStateWithDir initializes server state with persistence rooted at dir.
//
// On disk:
//   - creator-key.pem — PKCS#8-PEM-encoded P-256 private signing key.
//     Generated on first run; loaded on subsequent runs. The recipient pins
//     the matching pubkey, so this MUST be stable across restarts — losing
//     it breaks every existing recipient.
//   - configs.json — optional list of ConfigEntry records the issuer can
//     mint session credentials for. If absent, /v1/issue falls back to the
//     3.1a stub behavior so the wire-protocol test harness keeps working.
//
// Returns the populated *State or an error if the on-disk state is corrupt.
// A missing directory is auto-created (with 0700 perms); a missing
// creator-key.pem is generated. A missing configs.json is fine.
func NewStateWithDir(dir string) (*State, error) {
	if dir == "" {
		return NewState(), nil
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create state dir: %w", err)
	}

	priv, err := loadOrCreateCreatorKey(filepath.Join(dir, "creator-key.pem"))
	if err != nil {
		return nil, fmt.Errorf("creator key: %w", err)
	}

	hmacKey, err := loadOrCreateHmacKey(filepath.Join(dir, "vpn-hmac-key.bin"))
	if err != nil {
		return nil, fmt.Errorf("vpn hmac key: %w", err)
	}

	auditSalt, err := loadOrCreateAuditSalt(filepath.Join(dir, "audit-salt.bin"))
	if err != nil {
		return nil, fmt.Errorf("audit salt: %w", err)
	}

	configs, err := loadConfigsFile(filepath.Join(dir, "configs.json"))
	if err != nil {
		return nil, fmt.Errorf("configs.json: %w", err)
	}

	revocations, err := loadRevocationsFile(filepath.Join(dir, "revoked.json"))
	if err != nil {
		return nil, fmt.Errorf("revoked.json: %w", err)
	}

	redemptionTokensPath := filepath.Join(dir, "redemption-tokens.json")
	redemptionTokens, err := loadRedemptionTokensFile(redemptionTokensPath)
	if err != nil {
		return nil, fmt.Errorf("redemption-tokens.json: %w", err)
	}
	// Capture the file's mtime at load time so hot-reload knows whether
	// it's seen this version. Missing file → zero time (any later mtime
	// triggers a reload).
	var redemptionTokensMtime time.Time
	if info, statErr := os.Stat(redemptionTokensPath); statErr == nil {
		redemptionTokensMtime = info.ModTime()
	}

	return &State{
		CreatorSigningKey:     priv,
		VpnHmacKey:            hmacKey,
		AuditSalt:             auditSalt,
		stateDir:              dir,
		configs:               configs,
		revocations:           revocations,
		issuanceLimiter:       newRateLimiter(),
		verifierRegistry:      newVerifierRegistry(),
		redemptionTokens:      redemptionTokens,
		redemptionTokensPath:  redemptionTokensPath,
		redemptionTokensMtime: redemptionTokensMtime,
		redemptionLimiter:     newRateLimiter(),
	}, nil
}

// loadOrCreateAuditSalt reads a 32-byte salt from path. If absent,
// generates one and writes it (0600). Wrong-size files fail loudly —
// rotating the salt invalidates the correlation any existing audit
// log analysis depends on, so silent regeneration would be a footgun.
func loadOrCreateAuditSalt(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("read %s: %w", path, err)
		}
		salt := make([]byte, 32)
		if _, err := rand.Read(salt); err != nil {
			return nil, fmt.Errorf("generate audit salt: %w", err)
		}
		if err := os.WriteFile(path, salt, 0o600); err != nil {
			return nil, fmt.Errorf("write %s: %w", path, err)
		}
		return salt, nil
	}
	if len(data) != 32 {
		return nil, fmt.Errorf("%s: want 32 bytes, got %d (corrupt?)", path, len(data))
	}
	return data, nil
}

// loadOrCreateHmacKey reads a 32-byte HMAC key from path. If the file
// doesn't exist, generates one and writes it (0600). Returns the key bytes.
//
// Refusing to silently regenerate on parse failure is deliberate: the key
// is pre-shared with the VPN server, so dropping it without warning would
// break every existing tunnel. If the file exists but is the wrong size,
// it's almost certainly corruption.
func loadOrCreateHmacKey(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("read %s: %w", path, err)
		}
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return nil, fmt.Errorf("generate hmac key: %w", err)
		}
		if err := os.WriteFile(path, key, 0o600); err != nil {
			return nil, fmt.Errorf("write %s: %w", path, err)
		}
		return key, nil
	}
	if len(data) != 32 {
		return nil, fmt.Errorf("%s: want 32 bytes, got %d (corrupt?)", path, len(data))
	}
	return data, nil
}

// loadOrCreateCreatorKey reads a PKCS#8 PEM P-256 private key from path.
// If the file doesn't exist, generates a fresh key and writes it (0600).
// Any other error (corrupt file, wrong key type) is returned to the caller.
func loadOrCreateCreatorKey(path string) (*ecdsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("read %s: %w", path, err)
		}
		// First run: generate and persist.
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("generate key: %w", err)
		}
		der, err := x509.MarshalPKCS8PrivateKey(priv)
		if err != nil {
			return nil, fmt.Errorf("marshal key: %w", err)
		}
		blob := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
		if err := os.WriteFile(path, blob, 0o600); err != nil {
			return nil, fmt.Errorf("write %s: %w", path, err)
		}
		return priv, nil
	}

	block, _ := pem.Decode(data)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("%s: not a PEM PRIVATE KEY block", path)
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse PKCS8: %w", err)
	}
	priv, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%s: not an ECDSA key", path)
	}
	if priv.Curve != elliptic.P256() {
		return nil, fmt.Errorf("%s: not P-256", path)
	}
	return priv, nil
}

// loadConfigsFile reads configs.json. Returns nil (not an error) when the
// file is absent — the issuer falls back to stub behavior so cross-language
// tests still pass without a config registry.
//
// Validates that each entry has a unique configId (must be base64url-no-pad
// of exactly 16 raw bytes, matching what the envelope minter embeds in
// the header) and that any recipient-variant override is a JSON object.
// Operator typos surface here, not at the first recipient connect.
func loadConfigsFile(path string) (map[string]*ConfigEntry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var list []ConfigEntry
	if err := json.Unmarshal(data, &list); err != nil {
		return nil, fmt.Errorf("parse json: %w", err)
	}
	out := make(map[string]*ConfigEntry, len(list))
	for i := range list {
		entry := &list[i]
		if entry.ConfigID == "" {
			return nil, fmt.Errorf("entry %d: missing configId", i)
		}
		// configId must decode to exactly 16 bytes — that's the
		// envelope-header configId size (envelopeConfigIDLen). An
		// operator who hand-writes a random label like "fp-A" gets a
		// clean startup error here rather than every recipient's
		// connect 404'ing later (the bug 3.6g fixes).
		cid, err := b64url.DecodeString(entry.ConfigID)
		if err != nil {
			return nil, fmt.Errorf(
				"entry %d (configId=%s): not valid base64url-no-pad: %w",
				i, entry.ConfigID, err)
		}
		if len(cid) != envelopeConfigIDLen {
			return nil, fmt.Errorf(
				"entry %d (configId=%s): decodes to %d bytes; want %d (use the configId printed by `creator-server mint` / `mint-share-link`, NOT a hand-written label)",
				i, entry.ConfigID, len(cid), envelopeConfigIDLen)
		}
		if _, dup := out[entry.ConfigID]; dup {
			return nil, fmt.Errorf("entry %d: duplicate configId %s", i, entry.ConfigID)
		}
		// Config is required for any registered entry. An operator who
		// forgets it gets a clear startup error rather than recipients
		// silently receiving empty configB64 at runtime.
		if len(entry.Config) == 0 {
			return nil, fmt.Errorf(
				"entry %d (configId=%s): missing required field config", i, entry.ConfigID)
		}
		// Config must JSON-decode to an object (the ConfigBody shape).
		// A scalar or array here would break the deep-merge and the
		// sentinel substitution.
		var configProbe map[string]any
		if err := json.Unmarshal(entry.Config, &configProbe); err != nil {
			return nil, fmt.Errorf(
				"entry %d (configId=%s) config: not a JSON object: %w",
				i, entry.ConfigID, err)
		}
		// CredentialEncoding must be one we know how to render. An
		// unknown value would surface at every /v1/issue with a 500;
		// catching it here is cheaper.
		if !validCredentialEncoding(entry.CredentialEncoding) {
			return nil, fmt.Errorf(
				"entry %d (configId=%s) credentialEncoding=%q: must be one of \"uuid-v4\", \"base64url-raw\", or empty (defaults to base64url-raw)",
				i, entry.ConfigID, entry.CredentialEncoding)
		}
		// Each variant override must JSON-decode to an object so the
		// deep-merge in /v1/issue can rely on map shape. Empty objects
		// are fine (no-op override).
		for devicePk, variant := range entry.RecipientVariants {
			var probe map[string]any
			if err := json.Unmarshal(variant, &probe); err != nil {
				return nil, fmt.Errorf(
					"entry %d (configId=%s) recipientVariants[%s]: not a JSON object: %w",
					i, entry.ConfigID, devicePk, err,
				)
			}
		}
		// Attestation policy mode must be one of the recognized values.
		// An operator typo ("strikt"/"soft-fail"/etc.) would otherwise
		// silently behave as "off" — which is the worst-case (no
		// enforcement when the creator thought they were enforcing).
		if entry.AttestationPolicy != nil {
			if !validAttestationMode(entry.AttestationPolicy.Mode) {
				return nil, fmt.Errorf(
					"entry %d (configId=%s) attestationPolicy.mode = %q: must be off|observe|soft|strict",
					i, entry.ConfigID, entry.AttestationPolicy.Mode,
				)
			}
			if entry.AttestationPolicy.SoftFailureTtlSec < 0 {
				return nil, fmt.Errorf(
					"entry %d (configId=%s) attestationPolicy.softFailureTtlSec = %d: must be >= 0",
					i, entry.ConfigID, entry.AttestationPolicy.SoftFailureTtlSec,
				)
			}
			// Verifier name (if set) must be one we know about. An
			// unknown name almost certainly means a typo or a config
			// borrowed from a future version of the server — refusing
			// here is safer than silently no-op'ing.
			if entry.AttestationPolicy.Verifier != "" {
				registry := newVerifierRegistry()
				if _, err := registry.Lookup(entry.AttestationPolicy.Verifier); err != nil {
					return nil, fmt.Errorf(
						"entry %d (configId=%s) attestationPolicy.verifier: %w",
						i, entry.ConfigID, err,
					)
				}
				// App Attest needs a per-config appId in the policy.
				// Catching this at load time means an operator
				// fat-fingering apple-app-attest without setting
				// appId gets a clear startup error rather than every
				// iOS client silently failing attestation.
				if entry.AttestationPolicy.Verifier == "apple-app-attest" && entry.AttestationPolicy.AppID == "" {
					return nil, fmt.Errorf(
						"entry %d (configId=%s) attestationPolicy.verifier=apple-app-attest requires policy.appId (TEAMID.bundle.id)",
						i, entry.ConfigID,
					)
				}
			}
		}
		out[entry.ConfigID] = entry
	}
	return out, nil
}

// RedemptionToken is one row in state-dir/redemption-tokens.json — a
// publicly-shareable handle a creator hands out (typically as
// `npvtunnel://join?u=...&t=<token>` posted in a channel) that
// recipients trade in via POST /v1/redeem for a sealed V2 envelope
// addressed to their device.
//
// # The configId reuse property
//
// ConfigID is generated once at token creation and reused on every
// redemption of the same token. The envelope wire format defines
// configId as a stable identifier for "this is an update to a config I
// already have."
// So when a recipient redeems the same token from two devices, both
// envelopes share a configId — newest-issuedAt-wins reconciliation on
// each device handles refresh. When a creator wants a different
// logical config, they mint a different token (which gets a different
// configId).
type RedemptionToken struct {
	// Token is the bearer credential, base64url-no-pad of 16 random
	// bytes. Appears in the deep-link URL the creator posts publicly.
	Token string `json:"token"`

	// ConfigID is the routing key — must match a ConfigEntry.ConfigID
	// in configs.json. base64url-no-pad of 16 bytes. ALSO embedded
	// verbatim in every envelope minted for this token, so recipients
	// can read it back from the envelope header and send it to /v1/issue
	// (the same value plays both roles, no mismatch possible).
	ConfigID string `json:"configId"`

	// RemainingRedemptions caps how many recipients can redeem this
	// token. Decremented on each successful redemption. When it hits
	// 0, /v1/redeem returns 410 token_exhausted until the operator
	// either revokes the token or mints a new one.
	RemainingRedemptions int `json:"remainingRedemptions"`

	// ExpiresAt is the RFC3339 UTC wall-clock cutoff. Empty means no
	// expiry. After this time, /v1/redeem returns 410 token_expired
	// regardless of remaining count.
	ExpiresAt string `json:"expiresAt,omitempty"`

	// CreatedAt is informational. Useful for auditing token age in
	// the audit log.
	CreatedAt string `json:"createdAt"`

	// Label is an optional creator-side note, e.g. "telegram-channel-may-2026".
	// Audit log records carry this so a leak post-mortem can identify
	// which share-link the leaker came through. Never returned to the
	// recipient.
	Label string `json:"label,omitempty"`
}

// loadRedemptionTokensFile reads redemption-tokens.json. Missing file
// → empty map (no tokens). Duplicates fail loudly at startup; a real
// operator workflow always appends, so duplicates mean state-file
// corruption.
func loadRedemptionTokensFile(path string) (map[string]*RedemptionToken, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return map[string]*RedemptionToken{}, nil
		}
		return nil, err
	}
	var list []RedemptionToken
	if err := json.Unmarshal(data, &list); err != nil {
		return nil, fmt.Errorf("parse json: %w", err)
	}
	out := make(map[string]*RedemptionToken, len(list))
	for i := range list {
		entry := &list[i]
		if entry.Token == "" {
			return nil, fmt.Errorf("entry %d: missing token", i)
		}
		if entry.ConfigID == "" {
			return nil, fmt.Errorf("entry %d (token=%s): missing configId", i, shortBase64(entry.Token))
		}
		if _, dup := out[entry.Token]; dup {
			return nil, fmt.Errorf("entry %d: duplicate token %s", i, shortBase64(entry.Token))
		}
		out[entry.Token] = entry
	}
	return out, nil
}

// persistRedemptionTokens writes the in-memory token map to disk via
// write-then-rename for crash safety. Caller holds the State write
// lock for the map; this function does the file I/O.
func persistRedemptionTokens(path string, tokens map[string]*RedemptionToken) error {
	// Stable order in the file so manual operator review is sane.
	list := make([]RedemptionToken, 0, len(tokens))
	for _, v := range tokens {
		list = append(list, *v)
	}
	// Sort by CreatedAt ascending; ties broken by token for total order.
	sortRedemptionTokens(list)

	data, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("write tmp: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("rename: %w", err)
	}
	return nil
}

// sortRedemptionTokens orders tokens by CreatedAt, ties broken by
// Token. Pure function so persistence emits a deterministic file —
// reviewers see real diffs instead of map-order churn.
func sortRedemptionTokens(list []RedemptionToken) {
	// Simple insertion sort; the token list is small in practice.
	for i := 1; i < len(list); i++ {
		for j := i; j > 0 && redemptionTokenLess(list[j], list[j-1]); j-- {
			list[j], list[j-1] = list[j-1], list[j]
		}
	}
}

func redemptionTokenLess(a, b RedemptionToken) bool {
	if a.CreatedAt != b.CreatedAt {
		return a.CreatedAt < b.CreatedAt
	}
	return a.Token < b.Token
}

// RevocationEntry is one row in state-dir/revoked.json. Devices listed
// here are refused at /v1/issue with 403 device_revoked.
//
// The RevokedAt + Reason fields aren't required for the runtime check
// (only DevicePk is) but are useful for audit: when a creator looks back
// at why they kicked someone out six months ago, the reason is right
// there with the entry.
type RevocationEntry struct {
	// DevicePk is the recipient's signing pubkey, base64url-no-pad of
	// 33 bytes (P-256 SEC 1 compressed). Same form as IssueRequest.DevicePk.
	DevicePk string `json:"devicePk"`
	// RevokedAt is an ISO-8601 UTC timestamp. Informational.
	RevokedAt string `json:"revokedAt,omitempty"`
	// Reason is a short creator-facing note ("leaked technique 2026-05-27",
	// "device confirmed compromised", etc.). Informational.
	Reason string `json:"reason,omitempty"`
}

// loadRevocationsFile reads revoked.json. Missing file -> empty map (no
// revocations). The runtime check is by devicePk only; the other fields
// are kept for audit but unused at request time.
func loadRevocationsFile(path string) (map[string]*RevocationEntry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return map[string]*RevocationEntry{}, nil
		}
		return nil, err
	}
	var list []RevocationEntry
	if err := json.Unmarshal(data, &list); err != nil {
		return nil, fmt.Errorf("parse json: %w", err)
	}
	out := make(map[string]*RevocationEntry, len(list))
	for i := range list {
		entry := &list[i]
		if entry.DevicePk == "" {
			return nil, fmt.Errorf("entry %d: missing devicePk", i)
		}
		if _, dup := out[entry.DevicePk]; dup {
			return nil, fmt.Errorf("entry %d: duplicate devicePk %s", i, entry.DevicePk)
		}
		out[entry.DevicePk] = entry
	}
	return out, nil
}

// ConfigByID returns the registered ConfigEntry for configId, or nil
// if no registry is loaded or the configId isn't registered.
// Goroutine-safe.
func (s *State) ConfigByID(configID string) *ConfigEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.configs == nil {
		return nil
	}
	return s.configs[configID]
}

// HasConfigRegistry reports whether configs.json was loaded at startup.
// When false, /v1/issue should fall back to the 3.1a stub behavior.
func (s *State) HasConfigRegistry() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.configs != nil
}

// IsRevoked reports whether the given devicePk has been revoked. Returns
// the entry so the caller can include the reason in audit logs; nil if
// the device is not revoked.
func (s *State) IsRevoked(devicePk string) *RevocationEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.revocations == nil {
		return nil
	}
	return s.revocations[devicePk]
}

// ReloadRedemptionTokensIfChanged re-reads redemption-tokens.json
// from disk when its mtime is newer than the last load. Called from
// /v1/redeem at the top of every request — cheap (one os.Stat) on the
// common case where nothing changed; reloads only when the
// `mint-share-link` or `revoke-token` subcommand has bumped the file.
//
// # Why this exists
//
// The subcommands are separate `creator-server …` processes — they
// don't share memory with the running server. Without hot-reload, an
// operator running `mint-share-link` would have to `systemctl restart
// creator-server` before any recipient could redeem the new token.
// That's a real operational papercut (and was the bug 3.6g-3 fixes).
// On-mtime-change reload removes it.
//
// # What if the file's been removed
//
// We treat removal as "no tokens" — empty map, no error. The operator
// might have done `mv tokens.json tokens.json.bak` to disable
// redemption while keeping the file around; in either case, redemption
// stops working until a new file appears.
//
// # What about persists we did ourselves
//
// When the running server persists (via ConsumeRedemptionToken,
// AddRedemptionToken, RemoveRedemptionToken in-process), it updates
// redemptionTokensMtime to match the resulting file's mtime, so the
// next call here doesn't trigger a redundant reload. A second writer
// (separate `mint-share-link` process) bumps the file mtime to a value
// newer than the running server's, which DOES trigger reload — exactly
// the desired behavior.
//
// Persist failures (disk full, perms) are logged via the caller's
// logger and treated as "keep going with current in-memory state."
// Reload failures (corrupt JSON appeared on disk) are surfaced as an
// error the handler can map to a 500; we don't silently revert to an
// older in-memory state, since that would mask operator mistakes.
func (s *State) ReloadRedemptionTokensIfChanged() error {
	s.mu.RLock()
	path := s.redemptionTokensPath
	lastMtime := s.redemptionTokensMtime
	s.mu.RUnlock()

	if path == "" {
		// No persistence dir — nothing to reload.
		return nil
	}
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		// File gone. If we had tokens in-memory, drop them. Idempotent
		// when called repeatedly with no file.
		s.mu.Lock()
		defer s.mu.Unlock()
		if len(s.redemptionTokens) != 0 {
			s.redemptionTokens = map[string]*RedemptionToken{}
		}
		s.redemptionTokensMtime = time.Time{}
		return nil
	}
	if err != nil {
		return fmt.Errorf("stat %s: %w", path, err)
	}
	if !info.ModTime().After(lastMtime) {
		// File unchanged since our last load. Common case: no reload.
		return nil
	}

	// Reload under the write lock so a concurrent /v1/redeem doesn't
	// see a half-replaced map.
	fresh, err := loadRedemptionTokensFile(path)
	if err != nil {
		return fmt.Errorf("reload redemption-tokens.json: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.redemptionTokens = fresh
	s.redemptionTokensMtime = info.ModTime()
	return nil
}

// LookupRedemptionToken returns a read-only snapshot of the token entry,
// or nil if not registered. Used by the /v1/redeem handler for the
// "is this token plausible?" pre-check before doing the expensive
// envelope mint.
//
// Returning a value copy rather than a pointer means the caller can't
// concurrently mutate the in-memory entry — the only path that
// decrements is [ConsumeRedemptionToken] which takes its own write
// lock.
func (s *State) LookupRedemptionToken(token string) *RedemptionToken {
	s.mu.RLock()
	defer s.mu.RUnlock()
	entry, ok := s.redemptionTokens[token]
	if !ok {
		return nil
	}
	cp := *entry
	return &cp
}

// ConsumeRedemptionTokenResult tells the /v1/redeem handler why a
// consume attempt did or didn't succeed. Modeled on the existing
// rateLimiter decision type — explicit small struct beats a bool + 4
// out params.
type ConsumeRedemptionTokenResult struct {
	// Consumed is true when this call decremented the token.
	Consumed bool
	// Reason is the RedeemError code matching why Consumed is false.
	// Empty when Consumed is true.
	Reason string
}

// ConsumeRedemptionToken atomically validates and decrements a token.
// Returns Consumed=true exactly when this call succeeded in claiming
// one redemption slot. Persists redemption-tokens.json to disk on
// success.
//
// Failure modes (Reason set):
//   - token_not_found  — token doesn't exist
//   - token_exhausted  — RemainingRedemptions already 0 at lookup time
//   - token_expired    — ExpiresAt in the past
//
// The (lookup → check → decrement → persist) sequence is held under a
// single write lock so two concurrent redemptions can't both claim the
// last slot. The persist happens before the lock is released; if disk
// write fails we return server_error to the caller and the in-memory
// state still has the decrement (acceptable — slight over-decrement is
// safer than under, and the next successful redemption rewrites the
// file).
func (s *State) ConsumeRedemptionToken(token string, now time.Time) ConsumeRedemptionTokenResult {
	s.mu.Lock()
	defer s.mu.Unlock()

	entry, ok := s.redemptionTokens[token]
	if !ok {
		return ConsumeRedemptionTokenResult{Reason: "token_not_found"}
	}
	if entry.RemainingRedemptions <= 0 {
		return ConsumeRedemptionTokenResult{Reason: "token_exhausted"}
	}
	if entry.ExpiresAt != "" {
		expires, err := time.Parse(time.RFC3339, entry.ExpiresAt)
		if err == nil && now.After(expires) {
			return ConsumeRedemptionTokenResult{Reason: "token_expired"}
		}
	}

	entry.RemainingRedemptions--

	// Persist asynchronously-from-the-caller's-perspective but
	// synchronously inside the lock — keeps the on-disk state
	// consistent with what subsequent in-memory reads see. If the
	// write fails, log it but don't unroll the decrement: a creator
	// who lost disk space wants the rate-limiting property preserved
	// (subsequent redemptions still see the decrement) more than they
	// want a refund.
	if s.redemptionTokensPath != "" {
		if err := persistRedemptionTokens(s.redemptionTokensPath, s.redemptionTokens); err != nil {
			// Slog from inside state isn't wired; the handler will
			// see Consumed=true but can also choose to log via its
			// own logger. We return Consumed=true because the
			// in-memory state IS decremented; partial persist failure
			// is an operational concern, not a recipient-facing one.
			_ = err
		} else {
			// Track the mtime we just wrote so a subsequent reload
			// poll doesn't redundantly re-read the file we just
			// produced.
			if info, statErr := os.Stat(s.redemptionTokensPath); statErr == nil {
				s.redemptionTokensMtime = info.ModTime()
			}
		}
	}

	return ConsumeRedemptionTokenResult{Consumed: true}
}

// AddRedemptionToken inserts a freshly-minted token entry and
// persists. Used by the `mint-share-link` subcommand.
// Caller is responsible for filling in all fields; duplicates fail.
func (s *State) AddRedemptionToken(entry RedemptionToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, dup := s.redemptionTokens[entry.Token]; dup {
		return fmt.Errorf("token already exists")
	}
	cp := entry
	s.redemptionTokens[entry.Token] = &cp
	if s.redemptionTokensPath != "" {
		if err := persistRedemptionTokens(s.redemptionTokensPath, s.redemptionTokens); err != nil {
			return err
		}
		if info, statErr := os.Stat(s.redemptionTokensPath); statErr == nil {
			s.redemptionTokensMtime = info.ModTime()
		}
	}
	return nil
}

// RemoveRedemptionToken deletes a token (operator action via
// `revoke-token` subcommand). Returns whether the token existed.
func (s *State) RemoveRedemptionToken(token string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.redemptionTokens[token]; !ok {
		return false
	}
	delete(s.redemptionTokens, token)
	if s.redemptionTokensPath != "" {
		if err := persistRedemptionTokens(s.redemptionTokensPath, s.redemptionTokens); err == nil {
			if info, statErr := os.Stat(s.redemptionTokensPath); statErr == nil {
				s.redemptionTokensMtime = info.ModTime()
			}
		}
	}
	return true
}

// CreatorPubKeyCompressedB64 returns the base64url-no-pad encoding of the
// creator signing pubkey in SEC 1 compressed form (33 bytes). The recipient
// pins this value (either from a discovery envelope or from the test
// endpoint) and uses it to verify issuance receipts.
func (s *State) CreatorPubKeyCompressedB64() string {
	pub := &s.CreatorSigningKey.PublicKey
	// SEC 1 compressed: 0x02|0x03 prefix + 32-byte X.
	xBytes := pub.X.Bytes()
	out := make([]byte, 33)
	if pub.Y.Bit(0) == 0 {
		out[0] = 0x02
	} else {
		out[0] = 0x03
	}
	copy(out[33-len(xBytes):], xBytes)
	return b64url.EncodeToString(out)
}

// Close drops all in-memory state. Currently a no-op — all persistent
// state lives on disk and is flushed at write time.
func (s *State) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
}
