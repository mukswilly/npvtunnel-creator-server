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

// runMintSubcommand implements `creator-server mint`: it mints one signed
// "v2-issuer" envelope addressed to one or more recipients and prints its
// configId, config fingerprint, and base64url bytes to stdout (optionally also
// writing the raw bytes to a file). The envelope points recipients at this
// server's /v1/issue endpoint for the actual config.
//
// Key flags: -state-dir (holds creator-key.pem, required), -issuer-url (the
// https /v1/issue URL, required), -recipient-pubkey / -recipient-pubkeys-file
// (one or more P-256 compressed pubkeys, at least one required), -config-id
// (the configId to embed; generated if omitted), -out (write raw bytes), plus
// policy flags -expires-at, -display-message, -custom-server-message, and
// -only-mobile-network. Returns 0 on success, 2 for bad usage, 1 on failure.
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

	// Collect recipient pubkeys, validating each is a 33-byte P-256 compressed
	// key and dropping duplicates.
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

	// -recipient-pubkey may be repeated and each value may be comma-separated.
	for _, entry := range recipientPubkeys {
		for _, p := range strings.Split(entry, ",") {
			if err := addPubkey(p); err != nil {
				fmt.Fprintln(os.Stderr, "mint:", err)
				return 1
			}
		}
	}
	// The pubkeys file holds one key per line; blank and '#' lines are skipped.
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

	creatorKey, _, err := loadOrCreateCreatorKey(filepath.Join(*stateDir, "creator-key.pem"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "mint: load creator key:", err)
		return 1
	}

	// Build the envelope policy from the flags; attestation level is always NONE.
	pol := envelopePolicy{
		OnlyMobileNetwork:   *onlyMobile,
		AttestationLevel:    "NONE",
		ExpiresAt:           ptrOrNil(*expiresAtStr),
		DisplayMessage:      *displayMessage,
		CustomServerMessage: *customServerMessage,
	}

	// Validate the expiry format only when one was given.
	if *expiresAtStr != "" {
		if _, err := time.Parse(time.RFC3339, *expiresAtStr); err != nil {
			fmt.Fprintln(os.Stderr, "mint: -expires-at must be RFC3339:", err)
			return 2
		}
	}

	// Decode -config-id when supplied; leaving it nil lets the mint generate one.
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

	if *outFile != "" {
		if err := os.WriteFile(*outFile, res.EnvelopeBytes, 0o600); err != nil {
			fmt.Fprintln(os.Stderr, "mint: write -out file:", err)
			return 1
		}
		fmt.Fprintf(os.Stderr, "mint: wrote %d envelope bytes to %s\n",
			len(res.EnvelopeBytes), *outFile)
	}

	configIDB64 := b64url.EncodeToString(res.ConfigID)
	fmt.Printf("configId %s\n", configIDB64)
	fmt.Printf("configFp %s\n", res.ConfigFp)
	fmt.Printf("envelope %s\n", b64url.EncodeToString(res.EnvelopeBytes))

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

// multiStringFlag is a flag.Value that accumulates a string each time its flag
// is repeated on the command line.
type multiStringFlag []string

// String renders the accumulated values as a comma-separated list.
func (m *multiStringFlag) String() string { return strings.Join(*m, ",") }

// Set appends one occurrence of the flag's value.
func (m *multiStringFlag) Set(v string) error {
	*m = append(*m, v)
	return nil
}
