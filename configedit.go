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

// configedit.go adds the day-2 config operations the console was missing —
// rotate the credential, rename, remove — plus the direct (.npvs) handout. All
// of it edits state-dir/configs.json through the same readConfigEntries /
// writeConfigEntries used by `config add`; the running server hot-reloads it, so
// no restart is needed. The pure body-mutation helpers (setConfigCredential /
// setConfigName) are unit-tested without the UI.

// ─── per-config action hub ─────────────────────────────────────────────

func (c *console) showConfigActions(id string) {
	list := tview.NewList().ShowSecondaryText(true)
	list.SetSecondaryTextColor(tcell.ColorGray)
	list.AddItem("Mint a share link", "Public npvtunnel://join link for this config", '1', func() { c.showMint(id) })
	list.AddItem("Direct handout", "Mint a .npvs pointer for a device pubkey", '2', func() { c.showDirectMint(id) })
	list.AddItem("Rotate credential", "Replace the secret your VPN server accepts", '3', func() { c.showRotateCredential(id) })
	list.AddItem("Rename", "Change the display name", '4', func() { c.showRenameConfig(id) })
	list.AddItem("Remove", "Delete this config from the registry", '5', func() { c.confirmRemoveConfig(id) })
	list.AddItem("Back", "Return to the configs list", 'b', c.showConfigs)
	c.switchTo("configactions", "Config "+shortBase64(id), footerKeys("[yellow::b]Enter[-:-:-]=Select"), list)
}

// ─── rotate credential ─────────────────────────────────────────────────

func (c *console) showRotateCredential(id string) {
	var cred string
	form := tview.NewForm()
	form.AddPasswordField("New credential", "", 48, '*', func(t string) { cred = t })
	form.AddButton("Rotate", func() {
		cred = strings.TrimSpace(cred)
		if cred == "" {
			c.flash("Enter the new credential (the secret your VPN server now accepts).")
			return
		}
		err := c.updateConfigBody(id, func(b json.RawMessage) (json.RawMessage, error) {
			return setConfigCredential(b, cred)
		})
		if err != nil {
			c.flash("Couldn't rotate:\n\n" + err.Error())
			return
		}
		c.flashThen(
			"Credential rotated. The running server hot-reloads configs.json;\n"+
				"recipients pick up the new credential on their next fetch.",
			func() { c.showConfigActions(id) })
	})
	form.AddButton("Cancel", func() { c.showConfigActions(id) })
	form.SetBorder(true).SetTitle(" Rotate credential ")

	help := tview.NewTextView().SetDynamicColors(true).SetText(
		"\n  Paste the new credential AFTER you've rotated it on your VPN server\n" +
			"  (the VLESS UUID / SSH password it now accepts). The issuer hands this\n" +
			"  out verbatim — it never derives or mints it.")
	help.SetTextColor(tcell.ColorGray)

	body := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(form, 0, 1, true).
		AddItem(help, 5, 0, false)
	c.switchTo("rotate", "Rotate credential", footerKeys(""), body)
}

// ─── rename ────────────────────────────────────────────────────────────

func (c *console) showRenameConfig(id string) {
	cur := ""
	if list, err := readConfigEntries(filepath.Join(c.stateDir, "configs.json")); err == nil {
		for _, e := range list {
			if e.ConfigID == id {
				cur = summarizeConfig(e.Config).Name
			}
		}
	}
	name := cur
	form := tview.NewForm()
	form.AddInputField("Name", cur, 48, nil, func(t string) { name = t })
	form.AddButton("Save", func() {
		err := c.updateConfigBody(id, func(b json.RawMessage) (json.RawMessage, error) {
			return setConfigName(b, strings.TrimSpace(name))
		})
		if err != nil {
			c.flash("Couldn't rename:\n\n" + err.Error())
			return
		}
		c.flashThen("Renamed.", func() { c.showConfigActions(id) })
	})
	form.AddButton("Cancel", func() { c.showConfigActions(id) })
	form.SetBorder(true).SetTitle(" Rename config ")
	c.switchTo("rename", "Rename config", footerKeys(""), form)
}

// ─── remove ────────────────────────────────────────────────────────────

func (c *console) confirmRemoveConfig(id string) {
	c.confirm(fmt.Sprintf(
		"Remove config %s?\n\n"+
			"Share links pointing at it start returning 404 for new redemptions.\n"+
			"This only edits configs.json — your VPN server is untouched.",
		shortBase64(id)),
		func() {
			if err := c.removeConfig(id); err != nil {
				c.flash("Couldn't remove:\n\n" + err.Error())
				return
			}
			c.flashThen("Removed.", c.showConfigs)
		})
}

// ─── direct (.npvs) handout ────────────────────────────────────────────

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
	form.AddInputField("Recipient device pubkey (base64url)", "", 0, nil, func(t string) { pubkey = t })
	form.AddButton("Mint .npvs", func() {
		path, b64, err := c.mintDirect(selectedID, strings.TrimSpace(issuerURL), strings.TrimSpace(pubkey))
		if err != nil {
			c.flash("Couldn't mint:\n\n" + err.Error())
			return
		}
		c.flashThen(fmt.Sprintf(
			"Minted (carries no config — just a pointer).\n\nSaved to:\n%s\n\n"+
				"Or paste this to the recipient:\n\n%s", path, b64), c.showMain)
	})
	form.AddButton("Cancel", c.showMain)
	form.SetBorder(true).SetTitle(" Direct handout (.npvs) ")

	help := tview.NewTextView().SetDynamicColors(true).SetText(
		"\n  The recipient copies their device pubkey from the app and sends it to\n" +
			"  you. This mints a per-recipient .npvs pointer you send back through any\n" +
			"  channel. Set up your server first and the issuer URL fills in for you.")
	help.SetTextColor(tcell.ColorGray)

	body := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(form, 0, 1, true).
		AddItem(help, 5, 0, false)
	c.switchTo("directmint", "Direct handout", footerKeys(""), body)
}

// mintDirect validates the inputs and produces a per-recipient .npvs envelope,
// reusing the same mintIssuerEnvelope core the `mint` subcommand wraps. Returns
// the saved file path and the base64 envelope (for pasting).
func (c *console) mintDirect(configID, issuerURL, pubkeyB64 string) (path, b64 string, err error) {
	if issuerURL == "" {
		return "", "", fmt.Errorf("issuer URL is required\n(set up your server first, or type https://host/v1/issue)")
	}
	if !strings.HasPrefix(issuerURL, "https://") {
		return "", "", fmt.Errorf("issuer URL must start with https://")
	}
	raw, derr := b64url.DecodeString(pubkeyB64)
	if derr != nil {
		return "", "", fmt.Errorf("recipient pubkey isn't valid base64url: %w", derr)
	}
	if len(raw) != envelopeP256CompLen {
		return "", "", fmt.Errorf("recipient pubkey is %d bytes; want %d (P-256 compressed)", len(raw), envelopeP256CompLen)
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

// handoutFilename builds a per-(config,recipient) .npvs path under the state
// dir. base64url is filename-safe (only -, _, alnum), so short prefixes are fine.
func handoutFilename(stateDir, configID, pubkeyB64 string) string {
	short := func(s string) string {
		if len(s) > 8 {
			return s[:8]
		}
		return s
	}
	return filepath.Join(stateDir, "handout-"+short(configID)+"-"+short(pubkeyB64)+".npvs")
}

// ─── configs.json mutation helpers ─────────────────────────────────────

// updateConfigBody applies fn to the matching entry's config body and writes
// the registry back. fn receives the current body and returns the new one.
func (c *console) updateConfigBody(id string, fn func(json.RawMessage) (json.RawMessage, error)) error {
	path := filepath.Join(c.stateDir, "configs.json")
	list, err := readConfigEntries(path)
	if err != nil {
		return err
	}
	for i := range list {
		if list[i].ConfigID == id {
			nb, ferr := fn(list[i].Config)
			if ferr != nil {
				return ferr
			}
			list[i].Config = nb
			return writeConfigEntries(path, list)
		}
	}
	return fmt.Errorf("config %s not found in configs.json", shortBase64(id))
}

// removeConfig deletes the entry with the given configId from configs.json.
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

// ─── pure body mutators (unit-tested) ──────────────────────────────────

// setConfigCredential replaces the secret field in a config body, located by
// the body's `type` (V2RAY → v2rayProfile.password, SSH → sshConfig.sshPassword).
// Other fields are preserved byte-for-byte (values decoded as RawMessage).
func setConfigCredential(body json.RawMessage, newCred string) (json.RawMessage, error) {
	m, err := decodeObject(body)
	if err != nil {
		return nil, err
	}
	var typ string
	_ = json.Unmarshal(m["type"], &typ)
	switch strings.ToUpper(typ) {
	case "V2RAY":
		if err := setNestedString(m, "v2rayProfile", "password", newCred); err != nil {
			return nil, err
		}
	case "SSH":
		if err := setNestedString(m, "sshConfig", "sshPassword", newCred); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("config type %q isn't V2RAY or SSH — rotate the credential by editing configs.json directly", typ)
	}
	return json.Marshal(m)
}

// setConfigName replaces the top-level display name, preserving other fields.
func setConfigName(body json.RawMessage, name string) (json.RawMessage, error) {
	m, err := decodeObject(body)
	if err != nil {
		return nil, err
	}
	nb, _ := json.Marshal(name)
	m["name"] = nb
	return json.Marshal(m)
}

// decodeObject decodes a JSON object as a field map of raw values, so untouched
// fields round-trip without reformatting/precision loss.
func decodeObject(body json.RawMessage) (map[string]json.RawMessage, error) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(body, &m); err != nil {
		return nil, fmt.Errorf("config body is not a JSON object: %w", err)
	}
	return m, nil
}

// setNestedString sets m[outerKey][innerKey] = val, creating the inner object if
// absent and preserving its other fields.
func setNestedString(m map[string]json.RawMessage, outerKey, innerKey, val string) error {
	inner := map[string]json.RawMessage{}
	if raw, ok := m[outerKey]; ok && len(raw) > 0 {
		if err := json.Unmarshal(raw, &inner); err != nil {
			return fmt.Errorf("%s is not an object: %w", outerKey, err)
		}
	}
	vb, _ := json.Marshal(val)
	inner[innerKey] = vb
	nb, err := json.Marshal(inner)
	if err != nil {
		return err
	}
	m[outerKey] = nb
	return nil
}
