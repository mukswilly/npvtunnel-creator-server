package main

import (
	"crypto/rand"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

// menu.go is the interactive, full-screen management console —
// `creator-server menu` (and bare `creator-server` on a terminal). It's an
// app-like front end over the same state the flag subcommands use: register a
// config, list configs, mint and burn share links, check status, back up. The
// long-running issuer is a separate process (systemd); this is the creator's
// console for driving it.

const defaultConsoleStateDir = "/var/lib/creator-server"

// consoleSettings persists the small bits the console remembers between runs,
// so the creator doesn't retype them. Lives in <state-dir>/console.json.
type consoleSettings struct {
	RedemptionURL string `json:"redemptionUrl,omitempty"`
}

type console struct {
	app      *tview.Application
	pages    *tview.Pages
	stateDir string
	state    *State
	settings consoleSettings
}

func loadConsoleSettings(stateDir string) consoleSettings {
	var s consoleSettings
	if data, err := os.ReadFile(filepath.Join(stateDir, "console.json")); err == nil {
		_ = json.Unmarshal(data, &s)
	}
	return s
}

func (c *console) saveSettings() {
	if data, err := json.MarshalIndent(c.settings, "", "  "); err == nil {
		_ = os.WriteFile(filepath.Join(c.stateDir, "console.json"), data, 0o600)
	}
}

// newConsole builds the console (loads/creates state, wires the main menu) but
// does NOT start the event loop — so it can be exercised without a terminal.
func newConsole(stateDir string) (*console, error) {
	state, err := NewStateWithDir(stateDir)
	if err != nil {
		return nil, err
	}
	c := &console{
		app:      tview.NewApplication(),
		pages:    tview.NewPages(),
		stateDir: stateDir,
		state:    state,
		settings: loadConsoleSettings(stateDir),
	}
	c.app.SetInputCapture(func(ev *tcell.EventKey) *tcell.EventKey {
		switch ev.Key() {
		case tcell.KeyF3:
			c.app.Stop()
			return nil
		case tcell.KeyEscape:
			name, _ := c.pages.GetFrontPage()
			switch {
			case name == "modal":
				c.pages.RemovePage("modal") // Esc cancels a dialog
				return nil
			case name != "main" && name != "":
				c.showMain()
				return nil
			}
		}
		return ev
	})
	c.showMain()
	c.app.SetRoot(c.pages, true)
	return c, nil
}

// runMenuSubcommand handles `creator-server menu ...` — launches the console.
func runMenuSubcommand(args []string) int {
	fs := flag.NewFlagSet("menu", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	stateDir := fs.String("state-dir", defaultConsoleStateDir,
		"state directory (where your key + configs live)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	c, err := newConsole(*stateDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "menu: open state dir:", err)
		fmt.Fprintln(os.Stderr, "      pass -state-dir <dir> to choose where state lives.")
		return 1
	}
	if c.state.KeyWasCreated() {
		c.flash(fmt.Sprintf(
			"Welcome — your creator identity was just created.\n\n"+
				"Creator pubkey:\n%s\n\n"+
				"BACK IT UP (option 6). Lose %s\nand every recipient breaks.",
			c.state.CreatorPubKeyCompressedB64(),
			filepath.Join(c.stateDir, "creator-key.pem")))
	}
	c.app.EnableMouse(true)
	if err := c.app.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "menu:", err)
		return 1
	}
	return 0
}

// ─── chrome ────────────────────────────────────────────────────────────

func footerKeys(extra string) string {
	base := " [yellow::b]F3[-:-:-]=Exit  [yellow::b]Esc[-:-:-]=Back"
	if extra != "" {
		base += "  " + extra
	}
	return base
}

func (c *console) frame(title, keys string, body tview.Primitive) tview.Primitive {
	header := tview.NewTextView().SetDynamicColors(true)
	header.SetText(fmt.Sprintf(" [aqua::b]creator-server[-:-:-]   [white::b]%s[-:-:-]   [gray]%s", title, c.stateDir))
	footer := tview.NewTextView().SetDynamicColors(true)
	footer.SetText(keys)
	return tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(header, 1, 0, false).
		AddItem(body, 0, 1, true).
		AddItem(footer, 1, 0, false)
}

func (c *console) switchTo(name, title, keys string, body tview.Primitive) {
	c.pages.AddAndSwitchToPage(name, c.frame(title, keys, body), true)
}

func (c *console) modal(msg string, buttons []string, done func(int, string)) {
	m := tview.NewModal().SetText(msg).AddButtons(buttons).
		SetDoneFunc(func(i int, label string) {
			c.pages.RemovePage("modal")
			done(i, label)
		})
	c.pages.AddPage("modal", m, true, true)
}

func (c *console) flash(msg string)                  { c.modal(msg, []string{"OK"}, func(int, string) {}) }
func (c *console) flashThen(msg string, then func()) { c.modal(msg, []string{"OK"}, func(int, string) { then() }) }
func (c *console) confirm(msg string, yes func()) {
	c.modal(msg, []string{"Yes", "No"}, func(_ int, label string) {
		if label == "Yes" {
			yes()
		}
	})
}

// ─── main menu ─────────────────────────────────────────────────────────

func (c *console) showMain() {
	list := tview.NewList().ShowSecondaryText(true)
	list.SetSecondaryTextColor(tcell.ColorGray)
	list.AddItem("Register a config", "Paste the string your app exported (Export -> Copy for creator-server)", '1', c.showAddConfig)
	list.AddItem("Configs", "List the configs you hand out", '2', c.showConfigs)
	list.AddItem("Mint a share link", "Create a npvtunnel://join link to post", '3', func() { c.showMint("") })
	list.AddItem("Share links", "List and burn redemption tokens", '4', c.showTokens)
	list.AddItem("Server status", "Identity, counts, and how to run the server", '5', c.showStatus)
	list.AddItem("Back up state", "Save your key + configs to one file", '6', c.showBackup)
	list.AddItem("Sign off", "Exit the console", 'q', c.app.Stop)
	c.switchTo("main", "Main menu", footerKeys("[yellow::b]Up/Dn[-:-:-]=Move  [yellow::b]Enter[-:-:-]=Select"), list)
}

// ─── register a config ─────────────────────────────────────────────────

func (c *console) showAddConfig() {
	var configStr string
	form := tview.NewForm()
	form.AddInputField("Config string", "", 0, nil, func(t string) { configStr = t })
	form.AddButton("Register", func() {
		body, err := decodeConfigString(configStr)
		if err != nil {
			c.flash("That doesn't look like a config string:\n\n" + err.Error())
			return
		}
		id, err := c.appendConfig(body)
		if err != nil {
			c.flash("Couldn't save:\n\n" + err.Error())
			return
		}
		c.flashThen("Registered.\n\nconfigId:\n"+id+"\n\nMint a share link for it from the main menu.", c.showMain)
	})
	form.AddButton("Cancel", c.showMain)
	form.SetBorder(true).SetTitle(" Register a config ")

	help := tview.NewTextView().SetDynamicColors(true).SetText(
		"\n  In the app: open the config, then Export -> \"Copy for creator-server\",\n" +
			"  and paste it above. (Raw config JSON also works.)")
	help.SetTextColor(tcell.ColorGray)

	body := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(form, 0, 1, true).
		AddItem(help, 4, 0, false)
	c.switchTo("addconfig", "Register a config", footerKeys(""), body)
}

func (c *console) appendConfig(body json.RawMessage) (string, error) {
	idBytes := make([]byte, envelopeConfigIDLen)
	if _, err := rand.Read(idBytes); err != nil {
		return "", err
	}
	id := b64url.EncodeToString(idBytes)
	path := filepath.Join(c.stateDir, "configs.json")
	list, err := readConfigEntries(path)
	if err != nil {
		return "", err
	}
	list = append(list, ConfigEntry{ConfigID: id, Config: body})
	if err := writeConfigEntries(path, list); err != nil {
		return "", err
	}
	return id, nil
}

// ─── configs table ─────────────────────────────────────────────────────

func (c *console) showConfigs() {
	list, err := readConfigEntries(filepath.Join(c.stateDir, "configs.json"))
	if err != nil {
		c.flash("Couldn't read configs.json:\n\n" + err.Error())
		return
	}
	if len(list) == 0 {
		c.flashThen("No configs yet.\n\nRegister one from the main menu (option 1).", c.showMain)
		return
	}
	table := tview.NewTable().SetFixed(1, 0).SetSelectable(true, false)
	for i, h := range []string{"CONFIGID", "NAME", "TYPE", "ADDRESS"} {
		table.SetCell(0, i, headerCell(h))
	}
	for r, e := range list {
		s := summarizeConfig(e.Config)
		table.SetCell(r+1, 0, tview.NewTableCell(shortBase64(e.ConfigID)+"  "))
		table.SetCell(r+1, 1, tview.NewTableCell(orDash(s.Name)+"  "))
		table.SetCell(r+1, 2, tview.NewTableCell(orDash(s.Type)+"  "))
		table.SetCell(r+1, 3, tview.NewTableCell(orDash(s.Address)))
	}
	table.SetSelectedFunc(func(row, _ int) {
		if row >= 1 && row-1 < len(list) {
			c.showMint(list[row-1].ConfigID)
		}
	})
	c.switchTo("configs", "Configs", footerKeys("[yellow::b]Enter[-:-:-]=Mint link"), table)
}

// ─── mint a share link ─────────────────────────────────────────────────

func (c *console) showMint(prefillID string) {
	configs, err := readConfigEntries(filepath.Join(c.stateDir, "configs.json"))
	if err != nil {
		c.flash("Couldn't read configs.json:\n\n" + err.Error())
		return
	}
	if len(configs) == 0 {
		c.flashThen("Register a config first (main menu, option 1).", c.showMain)
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
	redemptionURL := c.settings.RedemptionURL
	redemptions := "100"
	expiresIn := "168h"
	label := ""

	form := tview.NewForm()
	form.AddDropDown("Config", options, initial, func(_ string, idx int) {
		if idx >= 0 && idx < len(configs) {
			selectedID = configs[idx].ConfigID
		}
	})
	form.AddInputField("Redemption URL", redemptionURL, 0, nil, func(t string) { redemptionURL = t })
	form.AddInputField("Redemptions", redemptions, 0, nil, func(t string) { redemptions = t })
	form.AddInputField("Expires in (e.g. 168h; 0 = never)", expiresIn, 0, nil, func(t string) { expiresIn = t })
	form.AddInputField("Label (optional)", "", 0, nil, func(t string) { label = t })
	form.AddButton("Mint link", func() {
		link, err := c.mintShareLink(selectedID, strings.TrimSpace(redemptionURL), redemptions, expiresIn, label)
		if err != nil {
			c.flash("Couldn't mint:\n\n" + err.Error())
			return
		}
		c.settings.RedemptionURL = strings.TrimSpace(redemptionURL)
		c.saveSettings()
		c.flashThen("Share link minted — post this in your channel:\n\n"+link, c.showMain)
	})
	form.AddButton("Cancel", c.showMain)
	form.SetBorder(true).SetTitle(" Mint a share link ")
	c.switchTo("mint", "Mint a share link", footerKeys(""), form)
}

func (c *console) mintShareLink(configID, redemptionURL, redemptionsStr, expiresIn, label string) (string, error) {
	if redemptionURL == "" {
		return "", fmt.Errorf("redemption URL is required\n(e.g. https://issuer.example/v1/redeem)")
	}
	if !strings.HasPrefix(redemptionURL, "https://") {
		return "", fmt.Errorf("redemption URL must start with https://")
	}
	redemptions, err := strconv.Atoi(strings.TrimSpace(redemptionsStr))
	if err != nil || redemptions <= 0 {
		return "", fmt.Errorf("redemptions must be a positive whole number")
	}
	expiresAt := ""
	if d := strings.TrimSpace(expiresIn); d != "" && d != "0" {
		dur, derr := time.ParseDuration(d)
		if derr != nil {
			return "", fmt.Errorf("expires in: %v (try 168h, 720h, 0)", derr)
		}
		if dur > 0 {
			expiresAt = time.Now().UTC().Add(dur).Format(time.RFC3339)
		}
	}
	tokenBytes := make([]byte, 16)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", err
	}
	token := b64url.EncodeToString(tokenBytes)
	if err := c.state.AddRedemptionToken(RedemptionToken{
		Token:                token,
		ConfigID:             configID,
		RemainingRedemptions: redemptions,
		ExpiresAt:            expiresAt,
		CreatedAt:            time.Now().UTC().Format(time.RFC3339),
		Label:                strings.TrimSpace(label),
	}); err != nil {
		return "", err
	}
	return fmt.Sprintf("npvtunnel://join?u=%s&t=%s",
		b64url.EncodeToString([]byte(redemptionURL)), token), nil
}

// ─── share links (tokens) table ────────────────────────────────────────

func (c *console) showTokens() {
	tokens, err := loadRedemptionTokensFile(filepath.Join(c.stateDir, "redemption-tokens.json"))
	if err != nil {
		c.flash("Couldn't read redemption-tokens.json:\n\n" + err.Error())
		return
	}
	if len(tokens) == 0 {
		c.flashThen("No share links yet.\n\nMint one from the main menu (option 3).", c.showMain)
		return
	}
	list := make([]RedemptionToken, 0, len(tokens))
	for _, t := range tokens {
		list = append(list, *t)
	}
	sortRedemptionTokens(list)
	now := time.Now().UTC()

	table := tview.NewTable().SetFixed(1, 0).SetSelectable(true, false)
	for i, h := range []string{"TOKEN", "CONFIG", "REMAIN", "EXPIRES", "LABEL", "STATUS"} {
		table.SetCell(0, i, headerCell(h))
	}
	for r, t := range list {
		status, code := tokenStatus(t, now)
		color := tcell.ColorGreen
		switch code {
		case statusExpiring:
			color = tcell.ColorYellow
		case statusExpired, statusExhausted:
			color = tcell.ColorRed
		}
		table.SetCell(r+1, 0, tview.NewTableCell(shortBase64(t.Token)+"  "))
		table.SetCell(r+1, 1, tview.NewTableCell(shortBase64(t.ConfigID)+"  "))
		table.SetCell(r+1, 2, tview.NewTableCell(strconv.Itoa(t.RemainingRedemptions)+"  "))
		table.SetCell(r+1, 3, tview.NewTableCell(expiryDisplay(t.ExpiresAt, now)+"  "))
		table.SetCell(r+1, 4, tview.NewTableCell(orDash(t.Label)+"  "))
		table.SetCell(r+1, 5, tview.NewTableCell(status).SetTextColor(color))
	}
	table.SetSelectedFunc(func(row, _ int) {
		if row >= 1 && row-1 < len(list) {
			tok := list[row-1]
			c.confirm(fmt.Sprintf(
				"Burn this share link?\n\n%s  (%s)\n\n"+
					"New redemptions get 404. Configs already issued through it keep\n"+
					"working until they expire.",
				shortBase64(tok.Token), orDash(tok.Label)),
				func() {
					c.state.RemoveRedemptionToken(tok.Token)
					c.showTokens()
				})
		}
	})
	c.switchTo("tokens", "Share links", footerKeys("[yellow::b]Enter[-:-:-]=Burn link"), table)
}

// ─── status ────────────────────────────────────────────────────────────

func (c *console) showStatus() {
	configs, _ := readConfigEntries(filepath.Join(c.stateDir, "configs.json"))
	tokens, _ := loadRedemptionTokensFile(filepath.Join(c.stateDir, "redemption-tokens.json"))
	now := time.Now().UTC()
	live := 0
	for _, t := range tokens {
		if _, code := tokenStatus(*t, now); code == statusLive || code == statusExpiring {
			live++
		}
	}
	text := fmt.Sprintf(
		"\n  [white::b]Creator identity[-:-:-]\n"+
			"  pubkey    %s\n"+
			"  key file  %s\n\n"+
			"  [white::b]Registry[-:-:-]\n"+
			"  configs       %d\n"+
			"  share links   %d total / %d live\n\n"+
			"  [white::b]Run the issuer[-:-:-] (on this VPS, as a service)\n"+
			"  creator-server -state-dir %s \\\n"+
			"      -domain <your-host> -acme-email <you@example>\n\n"+
			"  Built-in HTTPS via Let's Encrypt, no reverse proxy. Or use the\n"+
			"  one-line installer to set it up as a systemd service.\n",
		c.state.CreatorPubKeyCompressedB64(),
		filepath.Join(c.stateDir, "creator-key.pem"),
		len(configs), len(tokens), live, c.stateDir,
	)
	tv := tview.NewTextView().SetDynamicColors(true).SetText(text)
	c.switchTo("status", "Server status", footerKeys(""), tv)
}

// ─── backup ────────────────────────────────────────────────────────────

func (c *console) showBackup() {
	out := filepath.Join(c.stateDir, "creator-server-state-backup.tar.gz")
	c.confirm(
		"Back up your state (key, audit salt, configs, share links) to:\n\n"+out+"\n\n"+
			"Then copy it OFF this machine.",
		func() {
			n, total, err := writeStateBackup(c.stateDir, out)
			if err != nil {
				c.flash("Backup failed:\n\n" + err.Error())
				return
			}
			c.flash(fmt.Sprintf(
				"Backed up %d files (%d bytes) to:\n%s\n\n"+
					"Copy it somewhere safe, off this box.", n, total, out))
		})
}

// headerCell is a non-selectable bold yellow table header cell.
func headerCell(text string) *tview.TableCell {
	return tview.NewTableCell(text + "  ").
		SetTextColor(tcell.ColorYellow).
		SetAttributes(tcell.AttrBold).
		SetSelectable(false)
}
