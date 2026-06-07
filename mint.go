package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// runMintSubcommand handles `creator-server mint ...`. Loads the
// persisted creator key from the state dir, mints a V2 issuer
// envelope addressed to the supplied recipient, and prints the
// configId (routing key), configFp (integrity hash), and envelope
// bytes (all base64url-no-pad) on stdout in a machine-parseable format.
//
// Wire-compatible with the NpvTunnel client's envelope parser.
// Cross-language compat is asserted by the Go-side envelope_test.go
// round-trip + the manual dogfood we run after every codec change.
//
// Output format on stdout (one entry per line, machine-parseable):
//
//	configFp <base64url-no-pad>
//	configId <base64url-no-pad>
//	envelope <base64url-no-pad>
//
// Logs (creator pubkey, recipient fingerprint, etc.) go to stderr
// so stdout stays clean for piping.
func runMintSubcommand(args []string) int {
	fs := flag.NewFlagSet("mint", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	stateDir := fs.String("state-dir", "",
		"directory holding creator-key.pem (required — must match the running server)")
	var recipientPubkeys multiStringFlag
	fs.Var(&recipientPubkeys, "recipient-pubkey",
		"base64url-no-pad of a recipient's P-256 compressed pubkey (33 bytes). "+
			"For multiple recipients, repeat the flag or pass a comma-separated list.")
	recipientPubkeysFile := fs.String("recipient-pubkeys-file", "",
		"path to a file containing one base64url-no-pad recipient pubkey per line. "+
			"Combined with -recipient-pubkey flags if both supplied.")
	issuerURL := fs.String("issuer-url", "",
		"HTTPS URL of this server's /v1/issue endpoint (required)")
	expiresAtStr := fs.String("expires-at", "",
		"optional ISO-8601 envelope expiry (e.g. 2027-01-01T00:00:00Z)")
	displayMessage := fs.String("display-message", "",
		"optional policy.displayMessage shown to the recipient at import time")
	customServerMessage := fs.String("custom-server-message", "",
		"optional policy.customServerMessage")
	attestationLevel := fs.String("attestation-level", "NONE",
		"policy.attestationLevel: NONE | DEVICE_INTEGRITY | STRICT_PLAY_STORE")
	onlyMobile := fs.Bool("only-mobile-network", false,
		"policy.onlyMobileNetwork (recipient app warns / refuses when on Wi-Fi)")
	outFile := fs.String("out", "",
		"if set, write raw envelope bytes to this file (recipients import the file as-is); "+
			"the stdout summary still prints the base64 envelope too")

	if err := fs.Parse(args); err != nil {
		return 2
	}

	// Validate.
	if *stateDir == "" {
		fmt.Fprintln(os.Stderr, "mint: -state-dir is required (path to creator-key.pem)")
		fs.Usage()
		return 2
	}
	if *issuerURL == "" {
		fmt.Fprintln(os.Stderr, "mint: -issuer-url is required")
		return 2
	}
	if !strings.HasPrefix(*issuerURL, "https://") {
		fmt.Fprintln(os.Stderr, "mint: -issuer-url must start with https://")
		return 2
	}

	// Collect recipient pubkeys: -recipient-pubkey flags + the
	// optional file. Dedupe by raw bytes.
	var pubkeys [][]byte
	seen := map[string]bool{}
	addPubkey := func(b64 string) error {
		b64 = strings.TrimSpace(b64)
		if b64 == "" {
			return nil
		}
		raw, err := b64url.DecodeString(b64)
		if err != nil {
			return fmt.Errorf("decode %q: %w", b64, err)
		}
		if len(raw) != envelopeP256CompLen {
			return fmt.Errorf("recipient pubkey %q is %d bytes; want %d (P-256 compressed)",
				b64, len(raw), envelopeP256CompLen)
		}
		if seen[string(raw)] {
			return nil
		}
		seen[string(raw)] = true
		pubkeys = append(pubkeys, raw)
		return nil
	}
	// Each -recipient-pubkey occurrence may itself be a comma-separated
	// list, so a single flag can carry several recipients without
	// repeating it. (base64url has no commas, so the split is safe.)
	for _, entry := range recipientPubkeys {
		for _, p := range strings.Split(entry, ",") {
			if err := addPubkey(p); err != nil {
				fmt.Fprintln(os.Stderr, "mint:", err)
				return 1
			}
		}
	}
	if *recipientPubkeysFile != "" {
		f, err := os.Open(*recipientPubkeysFile)
		if err != nil {
			fmt.Fprintln(os.Stderr, "mint: open recipient file:", err)
			return 1
		}
		bs, err := io.ReadAll(f)
		f.Close()
		if err != nil {
			fmt.Fprintln(os.Stderr, "mint: read recipient file:", err)
			return 1
		}
		for _, line := range strings.Split(string(bs), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			if err := addPubkey(line); err != nil {
				fmt.Fprintln(os.Stderr, "mint:", err)
				return 1
			}
		}
	}
	if len(pubkeys) == 0 {
		fmt.Fprintln(os.Stderr,
			"mint: at least one recipient pubkey is required (via -recipient-pubkey or -recipient-pubkeys-file)")
		return 2
	}

	// Load creator key.
	creatorKey, err := loadOrCreateCreatorKey(filepath.Join(*stateDir, "creator-key.pem"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "mint: load creator key:", err)
		return 1
	}

	// Build policy.
	pol := envelopePolicy{
		OnlyMobileNetwork:   *onlyMobile,
		AttestationLevel:    *attestationLevel,
		ExpiresAt:           ptrOrNil(*expiresAtStr),
		DisplayMessage:      *displayMessage,
		CustomServerMessage: *customServerMessage,
	}

	// Parse expiresAt early so we fail fast on bad input.
	if *expiresAtStr != "" {
		if _, err := time.Parse(time.RFC3339, *expiresAtStr); err != nil {
			fmt.Fprintln(os.Stderr, "mint: -expires-at must be RFC3339:", err)
			return 2
		}
	}

	res, err := mintIssuerEnvelope(mintInput{
		CreatorKey:       creatorKey,
		RecipientPubKeys: pubkeys,
		IssuerURL:        *issuerURL,
		Policy:           &pol,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "mint:", err)
		return 1
	}

	// Optional file output.
	if *outFile != "" {
		if err := os.WriteFile(*outFile, res.EnvelopeBytes, 0o600); err != nil {
			fmt.Fprintln(os.Stderr, "mint: write -out file:", err)
			return 1
		}
		fmt.Fprintf(os.Stderr, "mint: wrote %d envelope bytes to %s\n",
			len(res.EnvelopeBytes), *outFile)
	}

	// Machine-parseable stdout. configId is the routing key the operator
	// pastes into configs.json. configFp is informational —
	// it's SHA-256(envelopeBytes), useful for verifying integrity of the
	// envelope file in transit but no longer used for issuer-side routing.
	configIDB64 := b64url.EncodeToString(res.ConfigID)
	fmt.Printf("configId %s\n", configIDB64)
	fmt.Printf("configFp %s\n", res.ConfigFp)
	fmt.Printf("envelope %s\n", b64url.EncodeToString(res.EnvelopeBytes))

	// Friendly stderr summary for human operators.
	fmt.Fprintf(os.Stderr,
		"\n--- mint summary ---\n"+
			"recipients:    %d\n"+
			"issuerUrl:     %s\n"+
			"configId:      %s\n"+
			"envelope size: %d bytes\n"+
			"\nAdd this entry to configs.json (the issuer returns config verbatim):\n"+
			`{
  "configId": "%s",
  "config": {
    "name":    "<display name>",
    "address": "<vpn-server>:<port>",
    "type":    "V2RAY",
    "v2rayProfile": {
      "server":     "<vpn-server>",
      "serverPort": "<port>",
      "password":   "a1b2c3d4-0000-4000-8000-000000000001",
      "// ...":     "the already-working credential your VPN server accepts"
    }
  },
  "attestationPolicy": { "mode": "off" }
}
`+"\n",
		len(pubkeys), *issuerURL, configIDB64, len(res.EnvelopeBytes),
		configIDB64,
	)

	return 0
}

// multiStringFlag is a flag.Value that collects all uses of the flag
// into a slice. Standard library doesn't expose this; trivial impl.
type multiStringFlag []string

func (m *multiStringFlag) String() string { return strings.Join(*m, ",") }
func (m *multiStringFlag) Set(v string) error {
	*m = append(*m, v)
	return nil
}
