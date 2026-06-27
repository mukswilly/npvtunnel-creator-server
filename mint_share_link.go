package main

import (
	"crypto/rand"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"
)

// newShareLink generates a random redemption token, persists it to state
// bound to configID (with its redemption budget, optional expiry, and label),
// and returns the token plus the join link that carries it. It does not verify
// that configID is registered; callers are expected to check first.
func newShareLink(state *State, configID, redemptionURL string, redemptions int, expiresAt, label string) (token, joinLink string, err error) {
	tokenBytes := make([]byte, 16)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", "", err
	}
	token = b64url.EncodeToString(tokenBytes)
	if err := state.AddRedemptionToken(RedemptionToken{
		Token:                token,
		ConfigID:             configID,
		RemainingRedemptions: redemptions,
		ExpiresAt:            expiresAt,
		CreatedAt:            time.Now().UTC().Format(time.RFC3339),
		Label:                label,
	}); err != nil {
		return "", "", err
	}
	return token, joinShareLink(redemptionURL, token), nil
}

// joinShareLink builds the join link a recipient opens to redeem: it encodes
// the redemption URL (base64url) and the token into the query so the recipient
// knows where to POST and with what token.
func joinShareLink(redemptionURL, token string) string {
	return fmt.Sprintf("npvtunnel://join?u=%s&t=%s",
		b64url.EncodeToString([]byte(redemptionURL)), token)
}

// runMintShareLinkSubcommand implements `creator-server mint-share-link`: it
// mints a redemption token for an already-registered config and prints the
// token, its configId, and the shareable join link. The config must exist in
// configs.json, else the command fails so a mistyped id surfaces here rather
// than at a recipient's first connect.
//
// Flags: -state-dir (required), -config-id (the registered configId, required),
// -redemption-url (the externally reachable https /v1/redeem URL, required),
// -redemptions (how many redemptions the token allows, default 100),
// -expires-in (token lifetime; 0 means no expiry), and -label (an audit note).
// Returns 0 on success, 2 for bad usage, 1 on failure.
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

	state, err := NewStateWithDir(*stateDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "mint-share-link: load state:", err)
		return 1
	}

	// Require a loaded registry and a matching entry before minting, so a bad
	// configId fails fast instead of producing a dead share link.
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

	// Translate the relative -expires-in into an absolute RFC3339 timestamp.
	expiresAt := ""
	if *expiresIn > 0 {
		expiresAt = time.Now().UTC().Add(*expiresIn).Format(time.RFC3339)
	}
	token, joinLink, err := newShareLink(state, *configID, *redemptionURL, *redemptions, expiresAt, *label)
	if err != nil {
		fmt.Fprintln(os.Stderr, "mint-share-link:", err)
		return 1
	}

	fmt.Printf("token       %s\n", token)
	fmt.Printf("configId    %s\n", *configID)
	fmt.Printf("join-link   %s\n", joinLink)

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

// runRevokeTokenSubcommand implements `creator-server revoke-token` (also the
// "token revoke" verb): it removes a redemption token from
// -state-dir/redemption-tokens.json so it can no longer be redeemed. It fails
// if the token is not registered. Flags: -state-dir (required) and -token (the
// token string to revoke, required). Returns 0 on success, 2 for bad usage, 1
// on failure.
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
