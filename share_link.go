package main

import (
	"crypto/rand"
	"fmt"
	"time"
)

// newShareLink creates the token behind a dashboard-generated share link.
func newShareLink(state *State, configIDs []string, redemptionURL string, redemptions int, expiresAt, label string) (token, joinLink string, err error) {
	tokenBytes := make([]byte, 16)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", "", err
	}
	token = b64url.EncodeToString(tokenBytes)
	if err := state.AddRedemptionToken(RedemptionToken{
		Token:                token,
		ConfigIDs:            append([]string(nil), configIDs...),
		RemainingRedemptions: redemptions,
		ExpiresAt:            expiresAt,
		CreatedAt:            time.Now().UTC().Format(time.RFC3339),
		Label:                label,
	}); err != nil {
		return "", "", err
	}
	return token, joinShareLink(redemptionURL, token), nil
}

func joinShareLink(redemptionURL, token string) string {
	return fmt.Sprintf("npvtunnel://join?u=%s&t=%s",
		b64url.EncodeToString([]byte(redemptionURL)), token)
}
