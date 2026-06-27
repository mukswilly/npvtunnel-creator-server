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

// ConfigEntry is a single registered configuration: the opaque payload served
// under its ConfigID together with the policy that governs how it may be issued.
// Entries are loaded from and persisted to configs.json on disk.
type ConfigEntry struct {
	// ConfigID is the base64url-no-pad identifier (envelopeConfigIDLen bytes
	// when decoded) under which this config is fetched.
	ConfigID string `json:"configId"`

	// Config is the opaque payload returned to a requester, kept as raw JSON
	// so it round-trips unchanged.
	Config json.RawMessage `json:"config"`

	// AttestationPolicy, when set, constrains issuance with attestation checks.
	AttestationPolicy *AttestationPolicy `json:"attestationPolicy,omitempty"`

	// IssuedPolicy stamps use restrictions onto each minted envelope.
	IssuedPolicy *envelopePolicy `json:"issuedPolicy,omitempty"`

	// ConfigTtlSec overrides the default envelope lifetime; 0 means use the
	// default. Validated against [configTtlMin, configTtlMax] at load time.
	ConfigTtlSec int `json:"configTtlSec,omitempty"`
}

// defaultMaxIssuancesPerHour caps issuances per requester for a config whose
// attestation policy does not set its own MaxIssuancesPerHour.
const defaultMaxIssuancesPerHour = 10

// defaultIssuanceLimitPerHour is the fallback per-config issuance rate cap.
const defaultIssuanceLimitPerHour = 30

// AttestationPolicy describes the attestation requirements a requester must
// satisfy before a config is issued, plus the knobs that tune enforcement.
type AttestationPolicy struct {
	// Mode selects the enforcement level: off, observe, soft, or strict.
	Mode string `json:"mode"`

	// SoftFailureTtlSec, in soft mode, bounds how long an issuance granted
	// despite a failed attestation check remains valid.
	SoftFailureTtlSec int `json:"softFailureTtlSec,omitempty"`

	// MaxIssuancesPerHour overrides defaultMaxIssuancesPerHour for this config.
	MaxIssuancesPerHour int `json:"maxIssuancesPerHour,omitempty"`

	// Verifier names the attestation verifier to apply (see verifierRegistry).
	Verifier string `json:"verifier,omitempty"`

	// RequireHardwareBacked demands the attestation key be hardware-backed.
	RequireHardwareBacked bool `json:"requireHardwareBacked,omitempty"`

	// RequireTrustedRoot demands the attestation chain terminate at a trusted root.
	RequireTrustedRoot bool `json:"requireTrustedRoot,omitempty"`

	// RequireVerifiedBoot demands the attestation assert a verified boot state.
	RequireVerifiedBoot bool `json:"requireVerifiedBoot,omitempty"`

	// AppID identifies the attesting application; required by some verifiers.
	AppID string `json:"appId,omitempty"`
}

// Attestation enforcement modes, ordered from no enforcement to strict.
const (
	AttestationModeOff     = "off"
	AttestationModeObserve = "observe"
	AttestationModeSoft    = "soft"
	AttestationModeStrict  = "strict"

	// defaultSoftFailureTtlSec is the soft-mode failure TTL when unspecified.
	defaultSoftFailureTtlSec = 300
)

// validAttestationMode reports whether m is one of the recognized modes.
func validAttestationMode(m string) bool {
	switch m {
	case AttestationModeOff, AttestationModeObserve, AttestationModeSoft, AttestationModeStrict:
		return true
	}
	return false
}

// State holds the server's mutable runtime state: the signing key, the
// in-memory config and redemption-token registries, their on-disk backing,
// and the rate limiters. All access is guarded by mu.
type State struct {
	// mu guards the registries and the cached file modification times.
	mu sync.RWMutex

	// CreatorSigningKey is the P-256 key used to sign issued payloads.
	CreatorSigningKey *ecdsa.PrivateKey

	// AuditSalt is a 32-byte salt mixed into audit-log hashing so logged
	// identifiers cannot be correlated across deployments.
	AuditSalt []byte

	// stateDir is the directory backing persistent state; empty for in-memory.
	stateDir string

	// configs maps ConfigID to its entry; nil when no registry is loaded.
	configs map[string]*ConfigEntry

	// configsPath is the configs.json path; configsMtime caches its last-seen
	// modification time for change detection during hot-reload.
	configsPath  string
	configsMtime time.Time

	// keyCreated is true when the signing key was freshly generated this run
	// rather than loaded from disk.
	keyCreated bool

	// issuanceLimiter rate-limits config issuance.
	issuanceLimiter *rateLimiter

	// verifierRegistry resolves attestation verifiers by name.
	verifierRegistry *verifierRegistry

	// PublicIssuerURL is the externally reachable base URL advertised to clients.
	PublicIssuerURL string

	// redemptionTokens maps a token string to its record; never nil.
	redemptionTokens map[string]*RedemptionToken

	// redemptionTokensPath is the redemption-tokens.json path;
	// redemptionTokensMtime caches its last-seen modification time.
	redemptionTokensPath string

	redemptionTokensMtime time.Time

	// redemptionLimiter rate-limits token redemption.
	redemptionLimiter *rateLimiter

	// TrustedProxies are CIDR ranges whose forwarded-for headers are honored
	// when deriving a request's client IP.
	TrustedProxies []*net.IPNet
}

// SweepRateLimiters drops rate-limiter entries older than window from both the
// issuance and redemption limiters.
func (s *State) SweepRateLimiters(window time.Duration) {
	s.issuanceLimiter.Sweep(window)
	s.redemptionLimiter.Sweep(window)
}

// NewState builds an in-memory State with a freshly generated signing key and
// audit salt and no on-disk backing. Nothing it creates survives a restart.
func NewState() *State {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic("ecdsa.GenerateKey: " + err.Error())
	}
	auditSalt := make([]byte, 32)
	if _, err := rand.Read(auditSalt); err != nil {
		panic("rand.Read for audit salt: " + err.Error())
	}
	return &State{
		CreatorSigningKey: priv,
		AuditSalt:         auditSalt,
		issuanceLimiter:   newRateLimiter(),
		verifierRegistry:  newVerifierRegistry(),
		redemptionTokens:  map[string]*RedemptionToken{},
		redemptionLimiter: newRateLimiter(),
	}
}

// NewStateWithDir builds a State backed by dir, creating the directory (0700)
// if needed. The signing key and audit salt are loaded from dir or generated
// and persisted on first use; the config and redemption-token registries are
// loaded from their JSON files, and each file's modification time is cached for
// later change detection. An empty dir yields an in-memory State.
func NewStateWithDir(dir string) (*State, error) {
	if dir == "" {
		return NewState(), nil
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create state dir: %w", err)
	}

	priv, keyCreated, err := loadOrCreateCreatorKey(filepath.Join(dir, "creator-key.pem"))
	if err != nil {
		return nil, fmt.Errorf("creator key: %w", err)
	}

	auditSalt, err := loadOrCreateAuditSalt(filepath.Join(dir, "audit-salt.bin"))
	if err != nil {
		return nil, fmt.Errorf("audit salt: %w", err)
	}

	configsPath := filepath.Join(dir, "configs.json")
	configs, err := loadConfigsFile(configsPath)
	if err != nil {
		return nil, fmt.Errorf("configs.json: %w", err)
	}
	// Cache the file's mtime so ReloadConfigsIfChanged can detect later edits.
	var configsMtime time.Time
	if info, statErr := os.Stat(configsPath); statErr == nil {
		configsMtime = info.ModTime()
	}

	redemptionTokensPath := filepath.Join(dir, "redemption-tokens.json")
	redemptionTokens, err := loadRedemptionTokensFile(redemptionTokensPath)
	if err != nil {
		return nil, fmt.Errorf("redemption-tokens.json: %w", err)
	}

	var redemptionTokensMtime time.Time
	if info, statErr := os.Stat(redemptionTokensPath); statErr == nil {
		redemptionTokensMtime = info.ModTime()
	}

	return &State{
		CreatorSigningKey:     priv,
		AuditSalt:             auditSalt,
		stateDir:              dir,
		configs:               configs,
		configsPath:           configsPath,
		configsMtime:          configsMtime,
		keyCreated:            keyCreated,
		issuanceLimiter:       newRateLimiter(),
		verifierRegistry:      newVerifierRegistry(),
		redemptionTokens:      redemptionTokens,
		redemptionTokensPath:  redemptionTokensPath,
		redemptionTokensMtime: redemptionTokensMtime,
		redemptionLimiter:     newRateLimiter(),
	}, nil
}

// KeyWasCreated reports whether the signing key was generated this run rather
// than loaded from disk.
func (s *State) KeyWasCreated() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.keyCreated
}

// loadOrCreateAuditSalt reads the 32-byte audit salt from path, or generates
// and persists a new one (0600) if the file does not exist. A file of any
// other length is treated as corrupt.
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

// loadOrCreateCreatorKey loads the P-256 signing key from the PKCS#8 PEM file
// at path, or generates a new key and writes it (0600) if the file does not
// exist. The bool result is true when a new key was created. A loaded key is
// rejected unless it is an ECDSA key on the P-256 curve.
func loadOrCreateCreatorKey(path string) (*ecdsa.PrivateKey, bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return nil, false, fmt.Errorf("read %s: %w", path, err)
		}

		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, false, fmt.Errorf("generate key: %w", err)
		}
		der, err := x509.MarshalPKCS8PrivateKey(priv)
		if err != nil {
			return nil, false, fmt.Errorf("marshal key: %w", err)
		}
		blob := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
		if err := os.WriteFile(path, blob, 0o600); err != nil {
			return nil, false, fmt.Errorf("write %s: %w", path, err)
		}
		return priv, true, nil
	}

	block, _ := pem.Decode(data)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, false, fmt.Errorf("%s: not a PEM PRIVATE KEY block", path)
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, false, fmt.Errorf("parse PKCS8: %w", err)
	}
	priv, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, false, fmt.Errorf("%s: not an ECDSA key", path)
	}
	if priv.Curve != elliptic.P256() {
		return nil, false, fmt.Errorf("%s: not P-256", path)
	}
	return priv, false, nil
}

// loadConfigsFile reads configs.json (a JSON array of ConfigEntry) at path and
// returns it as a ConfigID-keyed map. A missing file yields a nil map and no
// error (no registry configured). Every entry is fully validated: ConfigID must
// be present, decode from base64url-no-pad to envelopeConfigIDLen bytes, and be
// unique; config must be a non-empty JSON object; any attestation policy must
// have a valid mode, a non-negative soft-failure TTL, and a resolvable
// verifier; and configTtlSec, when set, must fall within [configTtlMin,
// configTtlMax]. Any violation aborts the load so a bad file is never swapped in.
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

		// ConfigID must decode to exactly the expected byte length.
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

		if len(entry.Config) == 0 {
			return nil, fmt.Errorf(
				"entry %d (configId=%s): missing required field config", i, entry.ConfigID)
		}

		// Confirm config is a JSON object (not an array, string, or number).
		var configProbe map[string]any
		if err := json.Unmarshal(entry.Config, &configProbe); err != nil {
			return nil, fmt.Errorf(
				"entry %d (configId=%s) config: not a JSON object: %w",
				i, entry.ConfigID, err)
		}

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

			if entry.AttestationPolicy.Verifier != "" {
				registry := newVerifierRegistry()
				if _, err := registry.Lookup(entry.AttestationPolicy.Verifier); err != nil {
					return nil, fmt.Errorf(
						"entry %d (configId=%s) attestationPolicy.verifier: %w",
						i, entry.ConfigID, err,
					)
				}

				if entry.AttestationPolicy.Verifier == "apple-app-attest" && entry.AttestationPolicy.AppID == "" {
					return nil, fmt.Errorf(
						"entry %d (configId=%s) attestationPolicy.verifier=apple-app-attest requires policy.appId (TEAMID.bundle.id)",
						i, entry.ConfigID,
					)
				}
			}
		}

		if entry.ConfigTtlSec != 0 {
			minSec := int(configTtlMin.Seconds())
			maxSec := int(configTtlMax.Seconds())
			if entry.ConfigTtlSec < minSec || entry.ConfigTtlSec > maxSec {
				return nil, fmt.Errorf(
					"entry %d (configId=%s) configTtlSec = %d: must be 0 (default) or within [%d, %d] seconds",
					i, entry.ConfigID, entry.ConfigTtlSec, minSec, maxSec,
				)
			}
		}
		out[entry.ConfigID] = entry
	}
	return out, nil
}

// RedemptionToken is a share-link token that can be exchanged for a minted
// envelope of the config it points at, until exhausted or expired. Tokens are
// loaded from and persisted to redemption-tokens.json.
type RedemptionToken struct {
	// Token is the opaque secret presented to redeem.
	Token string `json:"token"`

	// ConfigID is the config minted when this token is redeemed.
	ConfigID string `json:"configId"`

	// RemainingRedemptions is how many more times the token may be redeemed;
	// decremented on each successful redemption.
	RemainingRedemptions int `json:"remainingRedemptions"`

	// ExpiresAt is an optional RFC3339 expiry; empty means no expiry.
	ExpiresAt string `json:"expiresAt,omitempty"`

	// CreatedAt is the RFC3339 creation time, also the primary sort key.
	CreatedAt string `json:"createdAt"`

	// Label is an optional human-readable note.
	Label string `json:"label,omitempty"`
}

// loadRedemptionTokensFile reads redemption-tokens.json (a JSON array) at path
// and returns it keyed by token. A missing file yields an empty (non-nil) map.
// Each entry must carry a token and a configId, and tokens must be unique.
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

// persistRedemptionTokens writes the token map to path as a sorted JSON array.
// It writes to a sibling ".tmp" file and renames it into place so readers never
// observe a partially written file. Tokens are sorted for stable output.
func persistRedemptionTokens(path string, tokens map[string]*RedemptionToken) error {

	list := make([]RedemptionToken, 0, len(tokens))
	for _, v := range tokens {
		list = append(list, *v)
	}

	sortRedemptionTokens(list)

	data, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	// Atomic replace: write to a temp file, then rename over the target.
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("write tmp: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("rename: %w", err)
	}
	return nil
}

// sortRedemptionTokens sorts list in place by redemptionTokenLess using an
// insertion sort, which keeps the output deterministic.
func sortRedemptionTokens(list []RedemptionToken) {

	for i := 1; i < len(list); i++ {
		for j := i; j > 0 && redemptionTokenLess(list[j], list[j-1]); j-- {
			list[j], list[j-1] = list[j-1], list[j]
		}
	}
}

// redemptionTokenLess orders tokens by CreatedAt, breaking ties by Token.
func redemptionTokenLess(a, b RedemptionToken) bool {
	if a.CreatedAt != b.CreatedAt {
		return a.CreatedAt < b.CreatedAt
	}
	return a.Token < b.Token
}

// ConfigByID returns the entry for configID, or nil if no registry is loaded or
// no such entry exists.
func (s *State) ConfigByID(configID string) *ConfigEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.configs == nil {
		return nil
	}
	return s.configs[configID]
}

// HasConfigRegistry reports whether a config registry has been loaded (even if
// it is empty), distinguishing a configured-but-empty registry from none.
func (s *State) HasConfigRegistry() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.configs != nil
}

// ReloadConfigsIfChanged re-reads configs.json when its modification time has
// advanced past the cached value and swaps in the result. The new file is
// validated before the swap: if it fails to load, the last-good registry is
// kept and the error returned, but the cached mtime is still advanced so the
// same bad file is not retried on every poll. No-op when no path is configured
// or the file is absent.
func (s *State) ReloadConfigsIfChanged() error {
	s.mu.RLock()
	path := s.configsPath
	lastMtime := s.configsMtime
	s.mu.RUnlock()

	if path == "" {
		return nil
	}
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("stat %s: %w", path, err)
	}
	if !info.ModTime().After(lastMtime) {
		return nil
	}

	fresh, loadErr := loadConfigsFile(path)
	s.mu.Lock()
	defer s.mu.Unlock()

	s.configsMtime = info.ModTime()
	if loadErr != nil {
		return fmt.Errorf("reload configs.json (keeping last-good registry): %w", loadErr)
	}
	s.configs = fresh
	return nil
}

// ReloadRedemptionTokensIfChanged re-reads redemption-tokens.json when its
// modification time has advanced and swaps in the result. If the file has been
// removed, the in-memory token map is cleared and the cached mtime reset. No-op
// when no path is configured or the file is unchanged.
func (s *State) ReloadRedemptionTokensIfChanged() error {
	s.mu.RLock()
	path := s.redemptionTokensPath
	lastMtime := s.redemptionTokensMtime
	s.mu.RUnlock()

	if path == "" {

		return nil
	}
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		// File deleted out from under us: clear the registry to match.
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

		return nil
	}

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

// LookupRedemptionToken returns a copy of the named token's record, or nil if
// it is unknown. A copy is returned so callers cannot mutate shared state.
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

// ConsumeRedemptionTokenResult reports the outcome of ConsumeRedemptionToken.
type ConsumeRedemptionTokenResult struct {
	// Consumed is true when a redemption was successfully charged.
	Consumed bool

	// Reason gives the machine-readable cause when Consumed is false
	// (e.g. token_not_found, token_exhausted, token_expired).
	Reason string
}

// ConsumeRedemptionToken charges one redemption against token under the write
// lock, returning whether it succeeded. It rejects unknown, exhausted, and
// expired tokens. On success it decrements the remaining count and persists the
// updated token set, refreshing the cached mtime so the write is not mistaken
// for an external edit on the next reload poll.
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

	if s.redemptionTokensPath != "" {
		if err := persistRedemptionTokens(s.redemptionTokensPath, s.redemptionTokens); err != nil {
			// The in-memory decrement stands even if the disk write fails; the
			// redemption is honored rather than lost.
			_ = err
		} else {
			// Record the mtime of our own write so reload polling ignores it.
			if info, statErr := os.Stat(s.redemptionTokensPath); statErr == nil {
				s.redemptionTokensMtime = info.ModTime()
			}
		}
	}

	return ConsumeRedemptionTokenResult{Consumed: true}
}

// AddRedemptionToken inserts a new token, failing if one with the same Token
// already exists. A copy of entry is stored. When backed by disk, the updated
// set is persisted (propagating any write error) and the cached mtime refreshed
// so the write is not seen as an external edit.
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

// RemoveRedemptionToken deletes the named token, returning false if it was not
// present. On success the updated set is persisted and the cached mtime
// refreshed; a persist failure leaves the in-memory deletion in place.
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

// CreatorPubKeyCompressedB64 returns the signing public key as a base64url-no-pad
// SEC1 compressed point: a 33-byte value whose leading byte is 0x02 or 0x03
// (selected by the parity of Y) followed by the 32-byte big-endian X coordinate,
// right-aligned so any leading zero bytes of X are preserved.
func (s *State) CreatorPubKeyCompressedB64() string {
	pub := &s.CreatorSigningKey.PublicKey

	xBytes := pub.X.Bytes()
	out := make([]byte, 33)
	// Prefix encodes the sign of Y per SEC1 point compression.
	if pub.Y.Bit(0) == 0 {
		out[0] = 0x02
	} else {
		out[0] = 0x03
	}
	copy(out[33-len(xBytes):], xBytes)
	return b64url.EncodeToString(out)
}

// Close releases the State. It currently only acquires and releases the lock,
// serving as a quiescence point; no resources require explicit teardown.
func (s *State) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
}
