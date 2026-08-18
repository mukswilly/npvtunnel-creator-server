package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
	"unicode"
)

// stdinIsTTY reports whether standard input is a terminal. The server uses it
// to distinguish a creator opening the dashboard from systemd starting the
// unattended API process.
func stdinIsTTY() bool {
	info, err := os.Stdin.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

func readConfigEntries(path string) ([]ConfigEntry, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var list []ConfigEntry
	if err := json.Unmarshal(data, &list); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return list, nil
}

func writeConfigEntries(path string, list []ConfigEntry) error {
	data, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	return atomicWriteFile(path, data, 0o600)
}

type configSummary struct {
	Name    string `json:"name"`
	Address string `json:"address"`
	Type    string `json:"type"`
}

func summarizeConfig(raw json.RawMessage) configSummary {
	var summary configSummary
	_ = json.Unmarshal(raw, &summary)
	return summary
}

const maxDisplayNameRunes = 80

// normalizeDisplayName makes creator-visible aliases safe for terminal and app
// display while retaining ordinary Unicode names. An empty result means "use
// the name embedded in the registered config".
func normalizeDisplayName(value string) string {
	value = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, strings.TrimSpace(value))
	runes := []rune(strings.TrimSpace(value))
	if len(runes) > maxDisplayNameRunes {
		runes = runes[:maxDisplayNameRunes]
	}
	return string(runes)
}

// effectiveDisplayName returns an explicit creator alias when present and the
// config's own name otherwise.
func effectiveDisplayName(entry ConfigEntry) string {
	if alias := normalizeDisplayName(entry.DisplayName); alias != "" {
		return alias
	}
	return normalizeDisplayName(summarizeConfig(entry.Config).Name)
}

const configRegistrationKind = "npv-config-registration"

type registrationPolicy struct {
	blockRooted         bool
	iosAppID            string
	onlyMobileNetwork   bool
	expiresAt           string
	displayMessage      string
	customServerMessage string
}

// decodeConfigRegistration accepts a versioned registration exported by the
// app and returns its config body plus the creator-selected restrictions.
func decodeConfigRegistration(value string) (json.RawMessage, registrationPolicy, error) {
	var zero registrationPolicy
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, zero, fmt.Errorf("empty config string")
	}

	var candidate []byte
	if strings.HasPrefix(value, "{") {
		candidate = []byte(value)
	} else {
		decoded, err := b64url.DecodeString(value)
		if err != nil {
			return nil, zero, fmt.Errorf("config string is neither JSON nor base64url: %w", err)
		}
		candidate = decoded
	}

	var fields map[string]json.RawMessage
	if err := json.Unmarshal(candidate, &fields); err != nil {
		return nil, zero, fmt.Errorf("config string did not decode to a JSON object: %w", err)
	}
	if len(fields) == 0 {
		return nil, zero, fmt.Errorf("config decoded to an empty object")
	}

	var kind string
	if kindRaw, ok := fields["kind"]; !ok || json.Unmarshal(kindRaw, &kind) != nil || kind != configRegistrationKind {
		return nil, zero, fmt.Errorf("input is not an app registration export")
	}
	var version int
	if versionRaw, ok := fields["v"]; !ok || json.Unmarshal(versionRaw, &version) != nil || version != 1 {
		return nil, zero, fmt.Errorf("unsupported or missing registration version")
	}
	bodyRaw, ok := fields["config"]
	if !ok || len(bodyRaw) == 0 {
		return nil, zero, fmt.Errorf("registration export is missing its config body")
	}
	var policy registrationPolicy
	decode := func(key string, destination any) {
		if field, exists := fields[key]; exists {
			_ = json.Unmarshal(field, destination)
		}
	}
	decode("blockRooted", &policy.blockRooted)
	decode("iosAppId", &policy.iosAppID)
	decode("onlyMobileNetwork", &policy.onlyMobileNetwork)
	decode("expiresAt", &policy.expiresAt)
	decode("displayMessage", &policy.displayMessage)
	decode("customServerMessage", &policy.customServerMessage)
	body, err := compactJSONObject(bodyRaw)
	if err != nil {
		return nil, zero, err
	}
	if err := validateImportedConfig(body); err != nil {
		return nil, zero, err
	}
	return body, policy, nil
}

func validateImportedConfig(body json.RawMessage) error {
	var config struct {
		Type         string          `json:"type"`
		V2rayProfile json.RawMessage `json:"v2rayProfile"`
		SSHConfig    json.RawMessage `json:"sshConfig"`
	}
	if err := json.Unmarshal(body, &config); err != nil {
		return fmt.Errorf("decode imported config: %w", err)
	}
	switch config.Type {
	case "V2RAY":
		if _, err := compactJSONObject(config.V2rayProfile); err != nil {
			return fmt.Errorf("V2RAY registration is missing a valid v2rayProfile")
		}
	case "SSH":
		if _, err := compactJSONObject(config.SSHConfig); err != nil {
			return fmt.Errorf("SSH registration is missing a valid sshConfig")
		}
	default:
		return fmt.Errorf("registration contains unsupported config type %q", config.Type)
	}
	return nil
}

func issuedPolicyFrom(policy registrationPolicy) *envelopePolicy {
	if !policy.onlyMobileNetwork && policy.expiresAt == "" && policy.displayMessage == "" && policy.customServerMessage == "" {
		return nil
	}
	return &envelopePolicy{
		OnlyMobileNetwork:   policy.onlyMobileNetwork,
		AttestationLevel:    "NONE",
		ExpiresAt:           ptrOrNil(policy.expiresAt),
		DisplayMessage:      policy.displayMessage,
		CustomServerMessage: policy.customServerMessage,
	}
}

func compactJSONObject(raw json.RawMessage) (json.RawMessage, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil, fmt.Errorf("config body did not decode to a JSON object: %w", err)
	}
	if len(fields) == 0 {
		return nil, fmt.Errorf("config body decoded to an empty object")
	}
	var buffer bytes.Buffer
	if err := json.Compact(&buffer, raw); err != nil {
		return nil, fmt.Errorf("compact config JSON: %w", err)
	}
	return json.RawMessage(buffer.Bytes()), nil
}

type tokenStatusCode int

const (
	statusLive tokenStatusCode = iota
	statusExpiring
	statusExpired
	statusExhausted
)

func tokenStatus(token RedemptionToken, now time.Time) (string, tokenStatusCode) {
	if token.RemainingRedemptions <= 0 {
		return "exhausted", statusExhausted
	}
	if token.ExpiresAt != "" {
		if expiry, err := time.Parse(time.RFC3339, token.ExpiresAt); err == nil {
			if now.After(expiry) {
				return "expired", statusExpired
			}
			if expiry.Sub(now) < 24*time.Hour {
				return "expiring", statusExpiring
			}
		}
	}
	return "live", statusLive
}

func expiryDisplay(expiresAt string, now time.Time) string {
	if expiresAt == "" {
		return "never"
	}
	expiry, err := time.Parse(time.RFC3339, expiresAt)
	if err != nil {
		return expiresAt
	}
	duration := expiry.Sub(now)
	day := expiry.Format("2006-01-02")
	switch {
	case duration < 0:
		return day + " (passed)"
	case duration < time.Hour:
		return fmt.Sprintf("%s (%dm)", day, int(duration.Minutes()))
	case duration < 48*time.Hour:
		return fmt.Sprintf("%s (%dh)", day, int(duration.Hours()))
	default:
		return fmt.Sprintf("%s (%dd)", day, int(duration.Hours()/24))
	}
}

func orDash(value string) string {
	if value == "" {
		return "-"
	}
	return value
}
