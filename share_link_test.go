package main

import (
	"strings"
	"testing"
)

const testCID = "AAAAAAAAAAAAAAAAAAAAAA"

func TestNewShareLinkPersistsConfigSet(t *testing.T) {
	state, err := NewStateWithDir(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	configIDs := []string{testCID, "EBAQEBAQEBAQEBAQEBAQEA"}
	token, link, err := newShareLink(
		state,
		configIDs,
		"https://issuer.example/v1/redeem",
		50,
		"2027-01-01T00:00:00Z",
		"social",
	)
	if err != nil {
		t.Fatal(err)
	}
	if token == "" || !strings.HasPrefix(link, "npvtunnel://join?") {
		t.Fatalf("token=%q link=%q", token, link)
	}

	stored := state.LookupRedemptionToken(token)
	if stored == nil {
		t.Fatal("token was not stored")
	}
	got := stored.configIDs()
	if len(got) != 2 || got[0] != configIDs[0] || got[1] != configIDs[1] {
		t.Fatalf("configIDs = %q, want %q", got, configIDs)
	}
	if stored.RemainingRedemptions != 50 || stored.Label != "social" {
		t.Fatalf("stored token = %+v", stored)
	}
}

func TestAddRedemptionTokenRejectsInvalidConfigSets(t *testing.T) {
	state, err := NewStateWithDir(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name string
		ids  []string
	}{
		{name: "missing"},
		{name: "empty", ids: []string{""}},
		{name: "duplicate", ids: []string{testCID, testCID}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := state.AddRedemptionToken(RedemptionToken{Token: test.name, ConfigIDs: test.ids}); err == nil {
				t.Fatal("expected invalid config set to be rejected")
			}
		})
	}
}
