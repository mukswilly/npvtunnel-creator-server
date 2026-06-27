package main

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"
)

// stdinIsTTY reports whether standard input is a terminal (as opposed to a
// pipe or file), used to decide whether interactive prompting is appropriate.
func stdinIsTTY() bool {
	fi, err := os.Stdin.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

// colorEnabled reports whether ANSI color should be emitted: false when the
// NO_COLOR environment variable is set or when stdout is not a terminal.
func colorEnabled() bool {
	if _, set := os.LookupEnv("NO_COLOR"); set {
		return false
	}
	fi, err := os.Stdout.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

const (
	ansiReset  = "\x1b[0m"
	ansiBold   = "\x1b[1m"
	ansiDim    = "\x1b[2m"
	ansiRed    = "\x1b[31m"
	ansiGreen  = "\x1b[32m"
	ansiYellow = "\x1b[33m"
)

// paint wraps s in the given ANSI code (and a reset) when on is true,
// otherwise returns s unchanged.
func paint(on bool, code, s string) string {
	if !on {
		return s
	}
	return code + s + ansiReset
}

// promptLine writes label (with def shown in brackets when non-empty) to
// stderr, reads one line from r, and returns the trimmed input, falling back
// to def when the line is blank. The prompt goes to stderr so stdout stays
// reserved for machine-readable output.
func promptLine(r *bufio.Reader, label, def string) string {
	if def != "" {
		fmt.Fprintf(os.Stderr, "%s [%s]: ", label, def)
	} else {
		fmt.Fprintf(os.Stderr, "%s: ", label)
	}
	line, _ := r.ReadString('\n')
	line = strings.TrimSpace(line)
	if line == "" {
		return def
	}
	return line
}

// readConfigEntries reads and parses the configs.json registry at path. A
// missing file is not an error: it returns a nil slice so callers treat it as
// "no configs registered yet".
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

// writeConfigEntries writes list as indented JSON to path atomically, by
// writing a sibling .tmp file (mode 0600) and renaming it into place so a
// crash mid-write cannot leave a truncated registry.
func writeConfigEntries(path string, list []ConfigEntry) error {
	data, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// parseCreatorPubkey loads creator-key.pem from stateDir and returns the
// compressed P-256 public key in base64url form. It returns an empty string
// if the key file is absent or unparseable, so callers can show a "no key
// yet" state without failing.
func parseCreatorPubkey(stateDir string) string {
	data, err := os.ReadFile(filepath.Join(stateDir, "creator-key.pem"))
	if err != nil {
		return ""
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return ""
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return ""
	}
	priv, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return ""
	}
	return (&State{CreatorSigningKey: priv}).CreatorPubKeyCompressedB64()
}

// configSummary holds the few human-facing fields pulled out of a config body
// for display in listings.
type configSummary struct {
	Name    string `json:"name"`
	Address string `json:"address"`
	Type    string `json:"type"`
}

// summarizeConfig extracts the display fields from a config body, ignoring any
// fields it does not recognize. A decode failure yields a zero summary rather
// than an error.
func summarizeConfig(raw json.RawMessage) configSummary {
	var c configSummary
	_ = json.Unmarshal(raw, &c)
	return c
}

// runInitSubcommand implements `creator-server init`: it provisions a state
// directory (generating the signing key and an empty configs.json), then
// prints tailored instructions for running the server and registering configs.
// On a terminal it walks the operator through the choices interactively unless
// -non-interactive is given. Flags: -state-dir (where state lives), -domain
// (public hostname), -tls ("builtin" Let's Encrypt or "proxy" reverse proxy),
// -acme-email (ACME contact for builtin TLS), -non-interactive (skip prompts).
// Returns 0 on success, 2 for bad usage, 1 for I/O failures.
func runInitSubcommand(args []string) int {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	stateDir := fs.String("state-dir", "/var/lib/creator-server", "state directory to create")
	hostname := fs.String("domain", "", "public hostname (e.g. issuer.yourdomain.example)")
	tlsMode := fs.String("tls", "", "TLS mode: 'builtin' (Let's Encrypt) or 'proxy' (reverse proxy)")
	acmeEmail := fs.String("acme-email", "", "contact email for Let's Encrypt (builtin TLS)")
	noPrompt := fs.Bool("non-interactive", false, "never prompt; use flags/defaults only")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	// Prompt only on a real terminal and only when the operator hasn't opted out.
	interactive := stdinIsTTY() && !*noPrompt
	r := bufio.NewReader(os.Stdin)
	if interactive {
		fmt.Fprintln(os.Stderr, "creator-server setup  (Ctrl-C to abort; nothing is written until the end)")
		fmt.Fprintln(os.Stderr)
		*stateDir = promptLine(r, "State directory", *stateDir)
		*hostname = promptLine(r, "Public HTTPS hostname (e.g. issuer.yourdomain.example)", *hostname)
		if *tlsMode == "" {
			choice := promptLine(r, "TLS: 1) this binary via Let's Encrypt  2) a reverse proxy I run", "1")
			if strings.HasPrefix(choice, "2") {
				*tlsMode = "proxy"
			} else {
				*tlsMode = "builtin"
			}
		}
		if *tlsMode == "builtin" && *acmeEmail == "" {
			*acmeEmail = promptLine(r, "Contact email for Let's Encrypt (optional)", "")
		}
	}
	// Default to builtin TLS when nothing was chosen, then reject anything else.
	if *tlsMode == "" {
		*tlsMode = "builtin"
	}
	if *tlsMode != "builtin" && *tlsMode != "proxy" {
		fmt.Fprintf(os.Stderr, "init: -tls must be 'builtin' or 'proxy' (got %q)\n", *tlsMode)
		return 2
	}

	// Opening the state directory generates the signing key if it is absent.
	state, err := NewStateWithDir(*stateDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "init: create state:", err)
		return 1
	}
	pubkey := state.CreatorPubKeyCompressedB64()

	// Seed an empty registry so the server has a configs.json to hot-reload.
	configsPath := filepath.Join(*stateDir, "configs.json")
	if _, statErr := os.Stat(configsPath); errors.Is(statErr, os.ErrNotExist) {
		if werr := writeConfigEntries(configsPath, []ConfigEntry{}); werr != nil {
			fmt.Fprintln(os.Stderr, "init: write configs.json:", werr)
			return 1
		}
	}

	bold := colorEnabled()
	fmt.Fprintln(os.Stderr)
	fmt.Fprintf(os.Stderr, "State directory : %s\n", *stateDir)
	fmt.Fprintf(os.Stderr, "Creator pubkey  : %s  (recipients pin this)\n", pubkey)
	// A freshly generated key has no backup yet; warn loudly that losing it
	// invalidates every config already handed out.
	if state.KeyWasCreated() {
		fmt.Fprintln(os.Stderr, paint(bold, ansiYellow+ansiBold,
			"!! BACK UP "+filepath.Join(*stateDir, "creator-key.pem")+
				" now — lose it and every recipient breaks."))
		fmt.Fprintf(os.Stderr, "   creator-server backup -state-dir %s\n", *stateDir)
	}

	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, paint(bold, ansiBold, "Run the server:"))
	if *tlsMode == "builtin" {
		email := ""
		if *acmeEmail != "" {
			email = " -acme-email " + *acmeEmail
		}
		host := *hostname
		if host == "" {
			host = "issuer.yourdomain.example"
		}
		fmt.Fprintf(os.Stderr,
			"  creator-server -state-dir %s -domain %s%s\n"+
				"  (needs ports 80+443 reachable and DNS for %s pointing here)\n",
			*stateDir, host, email, host)
	} else {
		host := *hostname
		if host == "" {
			host = "issuer.yourdomain.example"
		}
		fmt.Fprintf(os.Stderr,
			"  creator-server -addr 127.0.0.1:8443 -state-dir %s \\\n"+
				"      -public-issuer-url https://%s/v1/issue\n"+
				"  then terminate TLS in front of 127.0.0.1:8443 (e.g. Caddy:\n"+
				"      %s { reverse_proxy 127.0.0.1:8443 })\n",
			*stateDir, host, host)
	}
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, paint(bold, ansiBold, "Next:"))
	fmt.Fprintln(os.Stderr, "  creator-server config add  -state-dir "+*stateDir+"   # register a config")
	fmt.Fprintln(os.Stderr, "  creator-server config ls   -state-dir "+*stateDir)
	fmt.Fprintln(os.Stderr, "  creator-server mint-share-link -state-dir "+*stateDir+" -config-id <id> \\")
	fmt.Fprintln(os.Stderr, "      -redemption-url https://<host>/v1/redeem -redemptions 100")
	return 0
}

// runConfigSubcommand dispatches `creator-server config` to its verbs: "ls"
// (alias "list") to print the registry and "add" to register a config.
func runConfigSubcommand(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "config: expected a verb: ls | add")
		return 2
	}
	switch args[0] {
	case "ls", "list":
		return runConfigLs(args[1:])
	case "add":
		return runConfigAdd(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "config: unknown verb %q (want: ls | add)\n", args[0])
		return 2
	}
}

// runConfigLs implements `config ls`: it reads the registry from
// -state-dir/configs.json and prints a column-aligned table of registered
// configs (id, name, type, address) to stdout. Requires -state-dir.
func runConfigLs(args []string) int {
	fs := flag.NewFlagSet("config ls", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	stateDir := fs.String("state-dir", "", "state directory (required)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *stateDir == "" {
		fmt.Fprintln(os.Stderr, "config ls: -state-dir is required")
		return 2
	}
	list, err := readConfigEntries(filepath.Join(*stateDir, "configs.json"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "config ls:", err)
		return 1
	}
	if len(list) == 0 {
		fmt.Fprintln(os.Stderr, "no configs registered. Add one with: creator-server config add -state-dir "+*stateDir)
		return 0
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "CONFIGID\tNAME\tTYPE\tADDRESS")
	for _, e := range list {
		c := summarizeConfig(e.Config)
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", shortBase64(e.ConfigID), orDash(c.Name), orDash(c.Type), orDash(c.Address))
	}
	tw.Flush()
	return 0
}

// runConfigAdd implements `config add`: it takes a config (an exported config
// string or raw JSON, via -config, -config-file, an interactive paste, or the
// -server/-port/-address quick-build), assigns it a fresh random configId, and
// appends it to -state-dir/configs.json. Any use restrictions carried in a
// registration bundle become the entry's issued policy, and a "block rooted"
// flag attaches a strict device-attestation policy. The new configId is
// printed to stdout. Requires -state-dir.
func runConfigAdd(args []string) int {
	fs := flag.NewFlagSet("config add", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	stateDir := fs.String("state-dir", "", "state directory (required)")
	configStr := fs.String("config", "",
		"the config string your app exported (Export -> \"Copy for creator-server\"). "+
			"Either the base64url config string or the raw config JSON. You do NOT "+
			"hand-write the app's config format — the app produces this for you.")
	configFile := fs.String("config-file", "",
		"read the config string / JSON from a file instead of -config")

	name := fs.String("name", "", "[advanced] V2RAY quick-build: display name")
	address := fs.String("address", "", "[advanced] V2RAY quick-build: server address host:port")
	server := fs.String("server", "", "[advanced] V2RAY quick-build: server host")
	port := fs.String("port", "", "[advanced] V2RAY quick-build: server port")
	password := fs.String("password", "", "[advanced] V2RAY quick-build: the value inside your config your VPN server accepts (advanced)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *stateDir == "" {
		fmt.Fprintln(os.Stderr, "config add: -state-dir is required")
		return 2
	}

	// Resolve the config text in priority order: -config, then -config-file.
	raw := strings.TrimSpace(*configStr)
	if raw == "" && *configFile != "" {
		data, err := os.ReadFile(*configFile)
		if err != nil {
			fmt.Fprintln(os.Stderr, "config add: read -config-file:", err)
			return 1
		}
		raw = strings.TrimSpace(string(data))
	}
	// Fall back to an interactive paste only when nothing was supplied, the
	// quick-build flags aren't in use, and stdin is a terminal.
	usingQuickBuild := *server != "" || *port != "" || *address != ""
	if raw == "" && !usingQuickBuild && stdinIsTTY() {
		r := bufio.NewReader(os.Stdin)
		fmt.Fprintln(os.Stderr,
			"Paste the config string from your app (Export -> \"Copy for creator-server\").")
		raw = strings.TrimSpace(promptLine(r, "config string", ""))
	}

	// Produce the config body and any policy: decode a pasted string/bundle,
	// or assemble a minimal V2RAY body from the quick-build flags.
	var body json.RawMessage
	var rp registrationPolicy
	switch {
	case raw != "":
		decoded, p, err := decodeConfigRegistration(raw)
		if err != nil {
			fmt.Fprintln(os.Stderr, "config add:", err)
			return 1
		}
		body = decoded
		rp = p
	case usingQuickBuild:
		if *server == "" || *port == "" || *address == "" {
			fmt.Fprintln(os.Stderr,
				"config add: the quick-build needs -server, -port and -address "+
					"(or just paste the app's config string with -config)")
			return 2
		}
		v2 := map[string]any{
			"name":    *name,
			"address": *address,
			"type":    "V2RAY",
			"v2rayProfile": map[string]any{
				"server":     *server,
				"serverPort": *port,
				"password":   *password,
			},
		}
		b, _ := json.Marshal(v2)
		body = b
	default:
		fmt.Fprintln(os.Stderr,
			"config add: paste the config string from your app with -config <string> "+
				"(or -config-file). Advanced: build a V2RAY config from -server/-port/-address.")
		return 2
	}

	// Mint a random configId for this entry.
	idBytes := make([]byte, envelopeConfigIDLen)
	if _, err := rand.Read(idBytes); err != nil {
		fmt.Fprintln(os.Stderr, "config add: rand:", err)
		return 1
	}
	configID := b64url.EncodeToString(idBytes)

	configsPath := filepath.Join(*stateDir, "configs.json")
	list, err := readConfigEntries(configsPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "config add:", err)
		return 1
	}
	entry := ConfigEntry{ConfigID: configID, Config: body}
	// A "block rooted" request gates issuance behind strict device attestation.
	if rp.blockRooted {

		entry.AttestationPolicy = strictDeviceAttestationPolicy()
	}

	// Carry any remaining use restrictions onto every envelope issued for it.
	entry.IssuedPolicy = issuedPolicyFrom(rp)
	list = append(list, entry)
	if err := writeConfigEntries(configsPath, list); err != nil {
		fmt.Fprintln(os.Stderr, "config add: write configs.json:", err)
		return 1
	}
	if rp.blockRooted {
		fmt.Fprintln(os.Stderr,
			"config add: device attestation REQUIRED — only stock, non-rooted "+
				"Android devices with verified boot will be issued this config.")
	}

	fmt.Printf("configId %s\n", configID)
	fmt.Fprintf(os.Stderr,
		"config add: registered configId %s (now %d total). "+
			"The running server hot-reloads configs.json. Hand it out with:\n"+
			"  creator-server mint-share-link -state-dir %s -config-id %s \\\n"+
			"      -redemption-url https://<host>/v1/redeem -redemptions 100\n",
		configID, len(list), *stateDir, configID)
	return 0
}

// configRegistrationKind is the value of the "kind" field that marks a config
// string as a registration bundle (a config body wrapped together with use
// restrictions) rather than a bare config object.
const configRegistrationKind = "npv-config-registration"

// registrationPolicy holds the use restrictions a registration bundle may
// carry alongside its config body.
type registrationPolicy struct {
	blockRooted         bool
	onlyMobileNetwork   bool
	expiresAt           string
	displayMessage      string
	customServerMessage string
}

// decodeConfigRegistration parses a config string into a compact config body
// and its policy. The input may be raw JSON (starting with '{') or base64url.
// When the decoded object is a registration bundle (kind ==
// configRegistrationKind) the inner "config" object is returned along with the
// bundle's restrictions; otherwise the object is treated as the config body
// itself and a zero policy is returned.
func decodeConfigRegistration(s string) (json.RawMessage, registrationPolicy, error) {
	var zero registrationPolicy
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, zero, fmt.Errorf("empty config string")
	}
	var candidate []byte
	if strings.HasPrefix(s, "{") {
		candidate = []byte(s)
	} else {
		dec, err := b64url.DecodeString(s)
		if err != nil {
			return nil, zero, fmt.Errorf("config string is neither JSON (starts with '{') nor base64url: %w", err)
		}
		candidate = dec
	}
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(candidate, &probe); err != nil {
		return nil, zero, fmt.Errorf("config string did not decode to a JSON object: %w", err)
	}
	if len(probe) == 0 {
		return nil, zero, fmt.Errorf("config decoded to an empty object")
	}

	if kindRaw, ok := probe["kind"]; ok {
		var kind string
		if json.Unmarshal(kindRaw, &kind) == nil && kind == configRegistrationKind {
			bodyRaw, ok := probe["config"]
			if !ok || len(bodyRaw) == 0 {
				return nil, zero, fmt.Errorf("registration bundle is missing its \"config\" body")
			}
			// Copy each known restriction out of the bundle when present,
			// leaving its zero value otherwise.
			var rp registrationPolicy
			into := func(key string, dst any) {
				if v, ok := probe[key]; ok {
					_ = json.Unmarshal(v, dst)
				}
			}
			into("blockRooted", &rp.blockRooted)
			into("onlyMobileNetwork", &rp.onlyMobileNetwork)
			into("expiresAt", &rp.expiresAt)
			into("displayMessage", &rp.displayMessage)
			into("customServerMessage", &rp.customServerMessage)
			body, err := compactJSONObject(bodyRaw)
			if err != nil {
				return nil, zero, err
			}
			return body, rp, nil
		}
	}

	body, err := compactJSONObject(candidate)
	if err != nil {
		return nil, zero, err
	}
	return body, zero, nil
}

// issuedPolicyFrom converts a registration policy into the per-envelope policy
// stamped onto issued configs. It returns nil when no envelope-level
// restriction is set (blockRooted is enforced separately via attestation, not
// here). The attestation level is always "NONE".
func issuedPolicyFrom(rp registrationPolicy) *envelopePolicy {
	if !rp.onlyMobileNetwork && rp.expiresAt == "" && rp.displayMessage == "" && rp.customServerMessage == "" {
		return nil
	}
	return &envelopePolicy{
		OnlyMobileNetwork:   rp.onlyMobileNetwork,
		AttestationLevel:    "NONE",
		ExpiresAt:           ptrOrNil(rp.expiresAt),
		DisplayMessage:      rp.displayMessage,
		CustomServerMessage: rp.customServerMessage,
	}
}

// compactJSONObject validates that raw is a non-empty JSON object and returns
// it with insignificant whitespace removed.
func compactJSONObject(raw json.RawMessage) (json.RawMessage, error) {
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(raw, &probe); err != nil {
		return nil, fmt.Errorf("config body did not decode to a JSON object: %w", err)
	}
	if len(probe) == 0 {
		return nil, fmt.Errorf("config body decoded to an empty object")
	}
	var buf bytes.Buffer
	if err := json.Compact(&buf, raw); err != nil {
		return nil, fmt.Errorf("compact config JSON: %w", err)
	}
	return json.RawMessage(buf.Bytes()), nil
}

// decodeConfigString returns just the config body from a config string,
// discarding any registration-bundle policy. It is the body-only form of
// decodeConfigRegistration.
func decodeConfigString(s string) (json.RawMessage, error) {
	body, _, err := decodeConfigRegistration(s)
	return body, err
}

// runTokenSubcommand dispatches `creator-server token` to its verbs: "ls"
// (alias "list") to print share-link tokens and "revoke" to delete one.
func runTokenSubcommand(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "token: expected a verb: ls | revoke")
		return 2
	}
	switch args[0] {
	case "ls", "list":
		return runTokenLs(args[1:])
	case "revoke":
		// Shares the implementation with the standalone revoke-token command.
		return runRevokeTokenSubcommand(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "token: unknown verb %q (want: ls | revoke)\n", args[0])
		return 2
	}
}

// runTokenLs implements `token ls`: it loads share-link tokens from
// -state-dir/redemption-tokens.json, sorts them, and prints a column-aligned
// table to stdout with each token's remaining redemptions, expiry, label, and
// a color-coded status (live/expiring/expired/exhausted). Requires -state-dir.
func runTokenLs(args []string) int {
	fs := flag.NewFlagSet("token ls", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	stateDir := fs.String("state-dir", "", "state directory (required)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *stateDir == "" {
		fmt.Fprintln(os.Stderr, "token ls: -state-dir is required")
		return 2
	}
	tokens, err := loadRedemptionTokensFile(filepath.Join(*stateDir, "redemption-tokens.json"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "token ls:", err)
		return 1
	}
	if len(tokens) == 0 {
		fmt.Fprintln(os.Stderr, "no share-link tokens. Mint one with: creator-server mint-share-link ...")
		return 0
	}

	list := make([]RedemptionToken, 0, len(tokens))
	for _, t := range tokens {
		list = append(list, *t)
	}
	sortRedemptionTokens(list)

	color := colorEnabled()
	now := time.Now().UTC()
	tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "TOKEN\tCONFIG\tREMAIN\tEXPIRES\tLABEL\tSTATUS")
	for _, t := range list {
		status, code := tokenStatus(t, now)
		colored := status
		switch code {
		case statusLive:
			colored = paint(color, ansiGreen, status)
		case statusExpiring:
			colored = paint(color, ansiYellow, status)
		case statusExpired, statusExhausted:
			colored = paint(color, ansiRed, status)
		}
		fmt.Fprintf(tw, "%s\t%s\t%d\t%s\t%s\t%s\n",
			shortBase64(t.Token), shortBase64(t.ConfigID), t.RemainingRedemptions,
			expiryDisplay(t.ExpiresAt, now), orDash(t.Label), colored)
	}
	tw.Flush()
	return 0
}

// tokenStatusCode classifies a share-link token's lifecycle state for display.
type tokenStatusCode int

const (
	// statusLive marks a token with redemptions left and no near-term expiry.
	statusLive tokenStatusCode = iota
	// statusExpiring marks a token expiring within 24 hours.
	statusExpiring
	// statusExpired marks a token whose expiry has passed.
	statusExpired
	// statusExhausted marks a token with no redemptions remaining.
	statusExhausted
)

// tokenStatus classifies t relative to now and returns both a display string
// and its code. Exhaustion is checked before expiry.
func tokenStatus(t RedemptionToken, now time.Time) (string, tokenStatusCode) {
	if t.RemainingRedemptions <= 0 {
		return "exhausted", statusExhausted
	}
	if t.ExpiresAt != "" {
		if exp, err := time.Parse(time.RFC3339, t.ExpiresAt); err == nil {
			if now.After(exp) {
				return "expired", statusExpired
			}
			if exp.Sub(now) < 24*time.Hour {
				return "expiring", statusExpiring
			}
		}
	}
	return "live", statusLive
}

// expiryDisplay formats an RFC3339 expiry for a table cell: "never" when
// empty, the raw string when unparseable, otherwise the date plus a relative
// hint such as "(3d)", "(5h)", "(12m)", or "(passed)".
func expiryDisplay(expiresAt string, now time.Time) string {
	if expiresAt == "" {
		return "never"
	}
	exp, err := time.Parse(time.RFC3339, expiresAt)
	if err != nil {
		return expiresAt
	}
	d := exp.Sub(now)
	day := exp.Format("2006-01-02")
	switch {
	case d < 0:
		return day + " (passed)"
	case d < time.Hour:
		return fmt.Sprintf("%s (%dm)", day, int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%s (%dh)", day, int(d.Hours()))
	default:
		return fmt.Sprintf("%s (%dd)", day, int(d.Hours()/24))
	}
}

// runStatusSubcommand implements `creator-server status`: it prints a summary
// of a state directory (the creator public key, the count of registered
// configs, and total vs. live share tokens) without starting the server.
// Missing or unreadable state degrades to zero counts rather than failing.
// Requires -state-dir.
func runStatusSubcommand(args []string) int {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	stateDir := fs.String("state-dir", "", "state directory (required)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *stateDir == "" {
		fmt.Fprintln(os.Stderr, "status: -state-dir is required")
		return 2
	}

	pubkey := parseCreatorPubkey(*stateDir)
	configs, _ := readConfigEntries(filepath.Join(*stateDir, "configs.json"))
	tokens, _ := loadRedemptionTokensFile(filepath.Join(*stateDir, "redemption-tokens.json"))

	// Count tokens still usable (live or expiring soon) as "live".
	now := time.Now().UTC()
	live := 0
	for _, t := range tokens {
		if _, code := tokenStatus(*t, now); code == statusLive || code == statusExpiring {
			live++
		}
	}

	keyStatus := pubkey
	if keyStatus == "" {
		keyStatus = "(none yet — run the server or `init` to generate)"
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintf(tw, "state-dir\t%s\n", *stateDir)
	fmt.Fprintf(tw, "creator pubkey\t%s\n", keyStatus)
	fmt.Fprintf(tw, "configs\t%d registered\n", len(configs))
	fmt.Fprintf(tw, "share tokens\t%d total / %d live\n", len(tokens), live)
	tw.Flush()
	return 0
}

// orDash returns s, or "-" when s is empty, so empty table cells render as a
// placeholder.
func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
