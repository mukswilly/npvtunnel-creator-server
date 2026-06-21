package main

import (
	"crypto/rand"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"
)

// runMintShareLinkSubcommand handles `creator-server mint-share-link ...`.
//
// Generates a random redemption token, validates that the named
// configId is already registered in configs.json, and appends a new
// entry to redemption-tokens.json. Outputs the
// `npvtunnel://join?u=<...>&t=<token>` deep link on stdout for the
// operator to paste into their channel.
//
// Share-link distribution: instead of posting a static config file in
// a public channel, the creator runs this command and posts its URL
// output. Recipients tap the URL, their app POSTs its pubkey to
// /v1/redeem and gets back a fully sealed per-recipient envelope.
//
// Output format on stdout (one entry per line, machine-parseable):
//
//	token       <random base64url>
//	configId    <as supplied via -config-id, echoed back>
//	join-link   npvtunnel://join?u=<base64url(redemptionUrl)>&t=<token>
//
// Friendly stderr summary for human operators.
func runMintShareLinkSubcommand(args []string) int {
	fs := flag.NewFlagSet("mint-share-link", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	stateDir := fs.String("state-dir", "",
		"directory holding creator-key.pem, configs.json, and "+
			"redemption-tokens.json (required — must match the running server)")
	configID := fs.String("config-id", "",
		"base64url-no-pad configId this token resolves to (the same value "+
			"that's in configs.json[].configId — get it from the `configId` "+
			"line of `creator-server mint` output, or generate fresh via "+
			"openssl rand -base64 16). Must already be registered in "+
			"configs.json — mint-share-link hard-fails otherwise so a typo "+
			"surfaces here instead of at the first recipient connect.")
	redemptionURL := fs.String("redemption-url", "",
		"externally-reachable URL of /v1/redeem on this server "+
			"(e.g. https://issuer.alpha.example/v1/redeem). Embedded in "+
			"the join link so recipients know where to POST.")
	redemptions := fs.Int("redemptions", 100,
		"how many recipients can redeem this token before it's exhausted")
	expiresIn := fs.Duration("expires-in", 0,
		"how long until the token stops being honored (0 = no expiry). "+
			"Examples: 168h (one week), 720h (~one month)")
	label := fs.String("label", "",
		"optional creator-side note. Surfaces in audit log records of "+
			"redemptions through this token. Useful for tracing leaks "+
			"back to a specific share channel.")

	if err := fs.Parse(args); err != nil {
		return 2
	}

	// Validate inputs.
	if *stateDir == "" {
		fmt.Fprintln(os.Stderr, "mint-share-link: -state-dir is required")
		fs.Usage()
		return 2
	}
	if *configID == "" {
		fmt.Fprintln(os.Stderr, "mint-share-link: -config-id is required")
		return 2
	}
	if *redemptionURL == "" {
		fmt.Fprintln(os.Stderr, "mint-share-link: -redemption-url is required")
		return 2
	}
	if !strings.HasPrefix(*redemptionURL, "https://") {
		fmt.Fprintln(os.Stderr, "mint-share-link: -redemption-url must start with https://")
		return 2
	}
	if *redemptions <= 0 {
		fmt.Fprintln(os.Stderr, "mint-share-link: -redemptions must be > 0")
		return 2
	}

	// Open the existing state directory. This loads configs.json so
	// we can validate the configId the operator named.
	state, err := NewStateWithDir(*stateDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "mint-share-link: load state:", err)
		return 1
	}

	// Hard-fail when configId isn't in configs.json. The configId is
	// the routing key — recipients send it back to /v1/issue. If the
	// share link points at a configId the issuer doesn't recognize,
	// every recipient's connect 404s — exactly the operator-typo bug this guards against.
	if !state.HasConfigRegistry() {
		fmt.Fprintln(os.Stderr,
			"mint-share-link: no configs.json registry loaded. "+
				"Register the config first, then mint a share link for it.")
		return 1
	}
	entry := state.ConfigByID(*configID)
	if entry == nil {
		fmt.Fprintf(os.Stderr,
			"mint-share-link: configId %q is not registered in configs.json. "+
				"Add an entry with this configId before minting a share link.\n",
			*configID)
		return 1
	}

	// Generate 16 random bytes for the token. base64url-no-pad gives
	// ~22 chars — short enough for a deep-link URL, long enough to be
	// unguessable.
	tokenBytes := make([]byte, 16)
	if _, err := rand.Read(tokenBytes); err != nil {
		fmt.Fprintln(os.Stderr, "mint-share-link: rand:", err)
		return 1
	}
	token := b64url.EncodeToString(tokenBytes)

	now := time.Now().UTC()
	expiresAt := ""
	if *expiresIn > 0 {
		expiresAt = now.Add(*expiresIn).Format(time.RFC3339)
	}

	tokenEntry := RedemptionToken{
		Token:                token,
		ConfigID:             *configID,
		RemainingRedemptions: *redemptions,
		ExpiresAt:            expiresAt,
		CreatedAt:            now.Format(time.RFC3339),
		Label:                *label,
	}
	if err := state.AddRedemptionToken(tokenEntry); err != nil {
		fmt.Fprintln(os.Stderr, "mint-share-link: register token:", err)
		return 1
	}

	// Build the join link. Format: npvtunnel://join?u=<base64url(redemptionUrl)>&t=<token>
	// The URL is base64'd so the URI parser doesn't fight with the
	// embedded colons/slashes. Token is base64url-no-pad (already
	// URI-safe) so it's plain.
	joinLink := fmt.Sprintf("npvtunnel://join?u=%s&t=%s",
		b64url.EncodeToString([]byte(*redemptionURL)),
		token,
	)

	// Machine-parseable stdout.
	fmt.Printf("token       %s\n", token)
	fmt.Printf("configId    %s\n", *configID)
	fmt.Printf("join-link   %s\n", joinLink)

	// Friendly stderr summary.
	expiryStr := "no expiry"
	if expiresAt != "" {
		expiryStr = expiresAt + " (in " + expiresIn.String() + ")"
	}
	fmt.Fprintf(os.Stderr,
		"\n--- mint-share-link summary ---\n"+
			"redemptions: %d\n"+
			"expires:     %s\n"+
			"label:       %q\n"+
			"\nPost this URL in your share channel:\n  %s\n",
		*redemptions, expiryStr, *label, joinLink,
	)

	return 0
}

// runRevokeTokenSubcommand handles `creator-server revoke-token ...`.
//
// Removes a token from redemption-tokens.json. A revoked token's
// future redemption attempts get 404 token_not_found. Existing
// envelopes already minted for past redemptions of this token still
// work — revocation kills the share link, not the per-recipient
// configs that were already issued through it.
func runRevokeTokenSubcommand(args []string) int {
	fs := flag.NewFlagSet("revoke-token", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	stateDir := fs.String("state-dir", "",
		"directory holding redemption-tokens.json (required)")
	token := fs.String("token", "",
		"the token string to revoke (the base64url value printed by "+
			"mint-share-link)")

	if err := fs.Parse(args); err != nil {
		return 2
	}

	if *stateDir == "" {
		fmt.Fprintln(os.Stderr, "revoke-token: -state-dir is required")
		return 2
	}
	if *token == "" {
		fmt.Fprintln(os.Stderr, "revoke-token: -token is required")
		return 2
	}

	state, err := NewStateWithDir(*stateDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "revoke-token: load state:", err)
		return 1
	}

	if !state.RemoveRedemptionToken(*token) {
		fmt.Fprintf(os.Stderr, "revoke-token: token %q not registered\n", *token)
		return 1
	}
	fmt.Fprintf(os.Stderr, "revoke-token: removed %q\n", *token)
	return 0
}
