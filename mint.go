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
// Produces envelope bytes in the documented .npvs wire format;
// envelope_test.go round-trips encode → decode → verify to assert the
// codec is self-consistent.
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
	configIDFlag := fs.String("config-id", "",
		"base64url-no-pad configId from `config add` (16 bytes). The minted "+
			"envelope embeds it so recipients route /v1/issue to the right "+
			"config. Omit to generate a fresh one (then register a config for it).")
	expiresAtStr := fs.String("expires-at", "",
		"optional ISO-8601 envelope expiry (e.g. 2027-01-01T00:00:00Z)")
	displayMessage := fs.String("display-message", "",
		"optional policy.displayMessage shown to the recipient at import time")
	customServerMessage := fs.String("custom-server-message", "",
		"optional policy.customServerMessage")
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
	creatorKey, _, err := loadOrCreateCreatorKey(filepath.Join(*stateDir, "creator-key.pem"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "mint: load creator key:", err)
		return 1
	}

	// Build policy. attestationLevel is always NONE: the envelope's signed
	// policy field is NOT the attestation gate — the runtime AttestationPolicy
	// on the configs.json entry (evaluated server-side at /v1/issue) is. A
	// recipient can't verify device attestation locally, so the app performs
	// none and refuses any non-NONE level; stamping one here would only break
	// import. Same reasoning as redeem.go, which mints with a nil (NONE) policy.
	pol := envelopePolicy{
		OnlyMobileNetwork:   *onlyMobile,
		AttestationLevel:    "NONE",
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

	// Optional fixed configId (from `config add`) so the direct-mint path
	// and the registered config line up. Absent → minter generates one.
	var configIDBytes []byte
	if *configIDFlag != "" {
		decoded, derr := b64url.DecodeString(*configIDFlag)
		if derr != nil || len(decoded) != envelopeConfigIDLen {
			fmt.Fprintf(os.Stderr, "mint: -config-id must be base64url-no-pad of %d bytes\n", envelopeConfigIDLen)
			return 2
		}
		configIDBytes = decoded
	}

	res, err := mintIssuerEnvelope(mintInput{
		CreatorKey:       creatorKey,
		RecipientPubKeys: pubkeys,
		IssuerURL:        *issuerURL,
		ConfigID:         configIDBytes,
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
			"\nNext: register the config this points at, under configId %s — paste the\n"+
			"string your app exported (Export -> \"Copy for creator-server\") as the\n"+
			"\"config\" value of a configs.json entry with that configId. The issuer\n"+
			"hands that config to the recipient verbatim. (The console does this for\n"+
			"you: register the config, then make a file for the device from it.)\n\n",
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
