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

// This file holds the operator-facing management CLI: a guided `init`
// wizard plus read/verb subcommands (config ls/add, token ls/revoke,
// status). Design goals: no extra dependencies (stdlib only), scriptable in
// a pipe AND friendly on a TTY (prompt-on-missing-input when interactive),
// and plain output that honors NO_COLOR.

// ─── TTY + color helpers ──────────────────────────────────────────────

// stdinIsTTY reports whether stdin is an interactive terminal (so we can
// prompt) vs. a pipe/redirect (so we stay scriptable and never block).
func stdinIsTTY() bool {
	fi, err := os.Stdin.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

// colorEnabled reports whether to emit ANSI color: only when stdout is a
// terminal and NO_COLOR is unset (https://no-color.org).
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

func paint(on bool, code, s string) string {
	if !on {
		return s
	}
	return code + s + ansiReset
}

// promptLine prints "label [def]: " and returns the typed line, or def on
// empty input. Caller should only invoke when stdinIsTTY().
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

// ─── config-entry file helpers (read/append without key side effects) ──

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
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// parseCreatorPubkey reads creator-key.pem (without creating it) and
// returns the pinned compressed pubkey, or "" if the file is absent.
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

// shortConfigName / configSummary pull display fields out of a config body.
type configSummary struct {
	Name    string `json:"name"`
	Address string `json:"address"`
	Type    string `json:"type"`
}

func summarizeConfig(raw json.RawMessage) configSummary {
	var c configSummary
	_ = json.Unmarshal(raw, &c)
	return c
}

// ─── init wizard ──────────────────────────────────────────────────────

// runInitSubcommand handles `creator-server init`: a one-shot guided setup
// that creates the state directory + signing key, ensures a configs.json
// exists, and prints the exact command to run the server (built-in TLS or
// behind a reverse proxy). Interactive on a TTY; flag/default-driven in a
// pipe.
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
	if *tlsMode == "" {
		*tlsMode = "builtin"
	}
	if *tlsMode != "builtin" && *tlsMode != "proxy" {
		fmt.Fprintf(os.Stderr, "init: -tls must be 'builtin' or 'proxy' (got %q)\n", *tlsMode)
		return 2
	}

	// Create state dir + key + audit salt (NewStateWithDir does all three).
	state, err := NewStateWithDir(*stateDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "init: create state:", err)
		return 1
	}
	pubkey := state.CreatorPubKeyCompressedB64()

	// Ensure a configs.json exists (empty registry) so the server runs in
	// registry mode and `config add` has a file to append to.
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
	if state.KeyWasCreated() {
		fmt.Fprintln(os.Stderr, paint(bold, ansiYellow+ansiBold,
			"!! BACK UP "+filepath.Join(*stateDir, "creator-key.pem")+
				" now — lose it and every recipient breaks."))
		fmt.Fprintf(os.Stderr, "   creator-server backup -state-dir %s\n", *stateDir)
	}

	// Recommend the run command.
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

// ─── config ls / add ──────────────────────────────────────────────────

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
	// Advanced escape hatch for operators who know the wire shape and want
	// to build a V2RAY config by hand instead of pasting the app's export.
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

	// Resolve the pasted config string from -config, -config-file, or an
	// interactive paste.
	raw := strings.TrimSpace(*configStr)
	if raw == "" && *configFile != "" {
		data, err := os.ReadFile(*configFile)
		if err != nil {
			fmt.Fprintln(os.Stderr, "config add: read -config-file:", err)
			return 1
		}
		raw = strings.TrimSpace(string(data))
	}
	usingQuickBuild := *server != "" || *port != "" || *address != ""
	if raw == "" && !usingQuickBuild && stdinIsTTY() {
		r := bufio.NewReader(os.Stdin)
		fmt.Fprintln(os.Stderr,
			"Paste the config string from your app (Export -> \"Copy for creator-server\").")
		raw = strings.TrimSpace(promptLine(r, "config string", ""))
	}

	var body json.RawMessage
	switch {
	case raw != "":
		decoded, err := decodeConfigString(raw)
		if err != nil {
			fmt.Fprintln(os.Stderr, "config add:", err)
			return 1
		}
		body = decoded
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

	// Fresh 16-byte configId (the routing key the envelope embeds).
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
	list = append(list, ConfigEntry{ConfigID: configID, Config: body})
	if err := writeConfigEntries(configsPath, list); err != nil {
		fmt.Fprintln(os.Stderr, "config add: write configs.json:", err)
		return 1
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

// decodeConfigString turns the string a creator pasted — the config their
// app exported, either base64url of the config body or the raw config JSON
// — into the config-body JSON the issuer stores and returns verbatim. The
// creator never has to know the config's field layout; the app produced it.
func decodeConfigString(s string) (json.RawMessage, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, fmt.Errorf("empty config string")
	}
	var candidate []byte
	if strings.HasPrefix(s, "{") {
		candidate = []byte(s) // already raw JSON
	} else {
		dec, err := b64url.DecodeString(s)
		if err != nil {
			return nil, fmt.Errorf("config string is neither JSON (starts with '{') nor base64url: %w", err)
		}
		candidate = dec
	}
	// Must be a non-empty JSON object. Decode values as RawMessage so nested
	// numbers/strings aren't reformatted or lose precision.
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(candidate, &probe); err != nil {
		return nil, fmt.Errorf("config string did not decode to a JSON object: %w", err)
	}
	if len(probe) == 0 {
		return nil, fmt.Errorf("config decoded to an empty object")
	}
	// Compact (preserves exact tokens) for stable on-disk storage.
	var buf bytes.Buffer
	if err := json.Compact(&buf, candidate); err != nil {
		return nil, fmt.Errorf("compact config JSON: %w", err)
	}
	return json.RawMessage(buf.Bytes()), nil
}

// ─── token ls / revoke ────────────────────────────────────────────────

func runTokenSubcommand(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "token: expected a verb: ls | revoke")
		return 2
	}
	switch args[0] {
	case "ls", "list":
		return runTokenLs(args[1:])
	case "revoke":
		// Alias for the legacy `revoke-token` subcommand.
		return runRevokeTokenSubcommand(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "token: unknown verb %q (want: ls | revoke)\n", args[0])
		return 2
	}
}

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
	// Stable order: by createdAt then token.
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

type tokenStatusCode int

const (
	statusLive tokenStatusCode = iota
	statusExpiring
	statusExpired
	statusExhausted
)

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

// ─── status ───────────────────────────────────────────────────────────

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

// ─── small helpers ────────────────────────────────────────────────────

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
