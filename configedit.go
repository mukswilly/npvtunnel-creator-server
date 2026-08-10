package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

// showConfigActions lists the actions available for a single registered config:
// make a share link, make a file for one device, replace the config body, or
// remove it.
func (c *console) showConfigActions(id string) {
	list := tview.NewList().ShowSecondaryText(true)
	list.SetSecondaryTextColor(tcell.ColorGray)
	list.AddItem("Share link", "npvtunnel://join to post in a channel (one or many people)", '1', func() { c.showMint(id) })
	list.AddItem("File for one device", "Make a .npvs file for someone whose device key you have", '2', func() { c.showDirectMint(id) })
	list.AddItem("Replace config", "Swap in a new export; existing links keep working", '3', func() { c.showReplaceConfig(id) })
	list.AddItem("Remove config", "Stop handing it out (everyone on it loses access)", '4', func() { c.confirmRemoveConfig(id) })
	list.AddItem("Back", "Return to the configs list", 'b', c.showConfigs)
	c.switchTo("configactions", "Config "+shortBase64(id), footerKeys("[yellow::b]Enter[-:-:-]=Select"), list)
}

// showReplaceConfig swaps a config's body in place, keeping the same configId so
// existing share links and handout files keep resolving.
func (c *console) showReplaceConfig(id string) {
	var configStr string
	form := tview.NewForm()
	form.AddInputField("New registration", "", 0, nil, func(t string) { configStr = t })
	form.AddButton("Replace", func() {
		body, policy, err := decodeConfigRegistration(strings.TrimSpace(configStr))
		if err != nil {
			c.flash("That registration could not be imported:\n\n" + err.Error())
			return
		}
		if err := c.replaceConfigRegistration(id, body, policy); err != nil {
			c.flash("Couldn't replace:\n\n" + err.Error())
			return
		}
		c.flashThen(
			"Config replaced. Your share links and handout files keep working —\n"+
				"people get the new config on their next connect.",
			func() { c.showConfigActions(id) })
	})
	form.AddButton("Cancel", func() { c.showConfigActions(id) })
	form.SetBorder(true).SetTitle(" Replace config ")

	help := tview.NewTextView().SetDynamicColors(true).SetText(
		"\n  Update the config and restrictions in the app, copy its server\n" +
			"  registration, and paste it here. Existing share links and handout\n" +
			"  files retain their identity and serve the replacement on refresh.")
	help.SetTextColor(tcell.ColorGray)

	body := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(form, 0, 1, true).
		AddItem(help, 5, 0, false)
	c.switchTo("replace", "Replace config", footerKeys(""), body)
}

// confirmRemoveConfig asks for confirmation before removing a config from the
// registry.
func (c *console) confirmRemoveConfig(id string) {
	c.confirm(fmt.Sprintf(
		"Remove config %s?\n\n"+
			"Everyone using it loses access on their next connect, and its share\n"+
			"links start returning \"not found\". This only edits your registry —\n"+
			"your VPN server is untouched.",
		shortBase64(id)),
		func() {
			if err := c.removeConfig(id); err != nil {
				c.flash("Couldn't remove:\n\n" + err.Error())
				return
			}
			c.flashThen("Removed.", c.showConfigs)
		})
}

// showDirectMint mints a .npvs file for one recipient whose device public key
// the operator already has. The config dropdown is prefilled to prefillID.
func (c *console) showDirectMint(prefillID string) {
	configs, err := readConfigEntries(filepath.Join(c.stateDir, "configs.json"))
	if err != nil {
		c.flash("Couldn't read configs.json:\n\n" + err.Error())
		return
	}
	if len(configs) == 0 {
		c.flashThen("Register a config first (main menu).", c.showMain)
		return
	}
	options := make([]string, len(configs))
	initial := 0
	for i, e := range configs {
		options[i] = shortBase64(e.ConfigID) + "  " + orDash(summarizeConfig(e.Config).Name)
		if e.ConfigID == prefillID {
			initial = i
		}
	}
	selectedID := configs[initial].ConfigID
	issuerURL := c.deploy().IssuerURL()
	pubkey := ""

	form := tview.NewForm()
	form.AddDropDown("Config", options, initial, func(_ string, idx int) {
		if idx >= 0 && idx < len(configs) {
			selectedID = configs[idx].ConfigID
		}
	})
	form.AddInputField("Issuer URL", issuerURL, 0, nil, func(t string) { issuerURL = t })
	form.AddInputField("Recipient's device key (base64url)", "", 0, nil, func(t string) { pubkey = t })
	form.AddButton("Make file", func() {
		path, b64, err := c.mintDirect(selectedID, strings.TrimSpace(issuerURL), strings.TrimSpace(pubkey))
		if err != nil {
			c.flash("Couldn't make the file:\n\n" + err.Error())
			return
		}
		c.flashThen(fmt.Sprintf(
			"Saved to:\n%s\n\nOr paste this to the recipient:\n\n%s", path, b64), c.showMain)
	})
	form.AddButton("Cancel", c.showMain)
	form.SetBorder(true).SetTitle(" File for one device ")

	help := tview.NewTextView().SetDynamicColors(true).SetText(
		"\n  Enter a recipient public key to create a .npvs file for that recipient.\n" +
			"  Set up the server first to prefill the issuer URL.")
	help.SetTextColor(tcell.ColorGray)

	body := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(form, 0, 1, true).
		AddItem(help, 4, 0, false)
	c.switchTo("directmint", "File for one device", footerKeys(""), body)
}

// mintDirect mints a v2-issuer envelope wrapped to a single recipient device
// key, writes it to a .npvs file in the state dir, and also returns the envelope
// base64url-encoded for pasting. The configId must be a valid 16-byte routing
// key already present in the registry.
func (c *console) mintDirect(configID, issuerURL, pubkeyB64 string) (path, b64 string, err error) {
	if issuerURL == "" {
		return "", "", fmt.Errorf("issuer URL is required\n(set up your server first, or type https://host/v1/issue)")
	}
	if !strings.HasPrefix(issuerURL, "https://") {
		return "", "", fmt.Errorf("issuer URL must start with https://")
	}
	raw, derr := b64url.DecodeString(pubkeyB64)
	if derr != nil {
		return "", "", fmt.Errorf("the device key isn't valid base64url: %w", derr)
	}
	if len(raw) != envelopeP256CompLen {
		return "", "", fmt.Errorf("the device key is %d bytes; want %d (P-256 compressed)", len(raw), envelopeP256CompLen)
	}
	cidBytes, derr := b64url.DecodeString(configID)
	if derr != nil || len(cidBytes) != envelopeConfigIDLen {
		return "", "", fmt.Errorf("configId %q is not a valid 16-byte routing key", configID)
	}

	res, merr := mintIssuerEnvelope(mintInput{
		CreatorKey:       c.state.CreatorSigningKey,
		RecipientPubKeys: [][]byte{raw},
		IssuerURL:        issuerURL,
		ConfigID:         cidBytes,
	})
	if merr != nil {
		return "", "", merr
	}

	out := handoutFilename(c.stateDir, configID, pubkeyB64)
	if werr := os.WriteFile(out, res.EnvelopeBytes, 0o600); werr != nil {
		return "", "", werr
	}
	return out, b64url.EncodeToString(res.EnvelopeBytes), nil
}

// handoutFilename builds a stable .npvs filename in the state dir from short
// prefixes of the configId and recipient key.
func handoutFilename(stateDir, configID, pubkeyB64 string) string {
	short := func(s string) string {
		if len(s) > 8 {
			return s[:8]
		}
		return s
	}
	return filepath.Join(stateDir, "handout-"+short(configID)+"-"+short(pubkeyB64)+".npvs")
}

// replaceConfigRegistration updates a config and its app-selected policies
// while retaining its routing identity and server-managed lifetime setting.
func (c *console) replaceConfigRegistration(id string, body json.RawMessage, policy registrationPolicy) error {
	path := filepath.Join(c.stateDir, "configs.json")
	list, err := readConfigEntries(path)
	if err != nil {
		return err
	}
	for i := range list {
		if list[i].ConfigID == id {
			list[i].Config = body
			list[i].AttestationPolicy = nil
			if policy.blockRooted {
				list[i].AttestationPolicy = strictDeviceAttestationPolicy(policy.iosAppID)
			}
			list[i].IssuedPolicy = issuedPolicyFrom(policy)
			return writeConfigEntries(path, list)
		}
	}
	return fmt.Errorf("config %s not found in configs.json", shortBase64(id))
}

// removeConfig drops the config with the given id from the registry file.
func (c *console) removeConfig(id string) error {
	path := filepath.Join(c.stateDir, "configs.json")
	list, err := readConfigEntries(path)
	if err != nil {
		return err
	}
	out := make([]ConfigEntry, 0, len(list))
	found := false
	for _, e := range list {
		if e.ConfigID == id {
			found = true
			continue
		}
		out = append(out, e)
	}
	if !found {
		return fmt.Errorf("config %s not found in configs.json", shortBase64(id))
	}
	return writeConfigEntries(path, out)
}
