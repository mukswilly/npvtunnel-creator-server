package main

import (
	"crypto/rand"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
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
	RedemptionURL string      `json:"redemptionUrl,omitempty"`
	Deployment    *deployment `json:"deployment,omitempty"`
}

// deployment records the server setup the console configured (or adopted), so
// it knows the domain/TLS without re-prompting and can derive issuer/redeem
// URLs. SetupComplete is the primary first-run signal (corroborated by unit
// presence on the adopt path).
type deployment struct {
	SetupComplete bool   `json:"setupComplete"`
	Domain        string `json:"domain,omitempty"`
	TLSMode       string `json:"tlsMode,omitempty"` // "builtin" | "proxy"
	Addr          string `json:"addr,omitempty"`
	AcmeEmail     string `json:"acmeEmail,omitempty"`
}

type console struct {
	app      *tview.Application
	pages    *tview.Pages
	stateDir string
	state    *State
	settings consoleSettings

	// Server-management seams — real implementations in production, fakes in
	// tests (so screens render without root, systemd, or the network).
	svc       serviceController
	health    healthChecker
	port      portChecker
	cert      certInspector
	canManage bool // may we run the privileged service verbs (root or sudo -n)?
}

// deploy resolves the current deployment: the persisted block first, else an
// adopt from an already-installed unit (install.sh user), else an unconfigured
// default. Always carries the console's own -state-dir.
func (c *console) deploy() DeployOpts {
	if d := c.settings.Deployment; d != nil && (d.SetupComplete || d.Domain != "") {
		return DeployOpts{
			BinPath:   defaultBinPath,
			StateDir:  c.stateDir,
			Mode:      parseTLSMode(d.TLSMode),
			Domain:    d.Domain,
			AcmeEmail: d.AcmeEmail,
			Addr:      d.Addr,
		}.withDefaults()
	}
	if o, ok := adoptFromUnit(serviceUnitPath); ok {
		o.StateDir = c.stateDir
		return o.withDefaults()
	}
	return DeployOpts{StateDir: c.stateDir}.withDefaults()
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
		app:       tview.NewApplication(),
		pages:     tview.NewPages(),
		stateDir:  stateDir,
		state:     state,
		settings:  loadConsoleSettings(stateDir),
		svc:       newSystemctlController(),
		health:    httpHealthChecker{},
		port:      dialPortChecker{},
		cert:      autocertInspector{},
		canManage: canManageSystemd(),
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
	// Route by setup state: a brand-new box gets the wizard; an install.sh user
	// (unit but no console.json) is adopted onto the Server screen; an
	// already-configured box goes straight to the menu.
	state := c.detectSetupState()
	switch state {
	case setupAdopt:
		c.adoptDeployment()
		c.showServer()
	case setupFirstRun:
		c.showSetupWizard()
	}
	// The wizard gates on backup itself; on the other paths, nudge if this run
	// just generated the signing key.
	if state != setupFirstRun && c.state.KeyWasCreated() {
		c.flash(fmt.Sprintf(
			"Welcome — your creator identity was just created.\n\n"+
				"Creator pubkey:\n%s\n\n"+
				"BACK IT UP (Back up state). Lose %s\nand every recipient breaks.",
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

func (c *console) flash(msg string) { c.modal(msg, []string{"OK"}, func(int, string) {}) }
func (c *console) flashThen(msg string, then func()) {
	c.modal(msg, []string{"OK"}, func(int, string) { then() })
}
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
	list.AddItem("Configs", "List, share, replace, remove your configs", '2', c.showConfigs)
	list.AddItem("Mint a share link", "Create a npvtunnel://join link to post", '3', func() { c.showMint("") })
	list.AddItem("Direct handout", "Mint a .npvs pointer for a device pubkey", '4', func() { c.showDirectMint("") })
	list.AddItem("Share links", "List and burn redemption tokens", '5', c.showTokens)
	list.AddItem("Server", "Service health, TLS, identity, and controls", '6', c.showServer)
	list.AddItem("Back up state", "Save your key + configs to one file", '7', c.showBackup)
	list.AddItem("Sign off", "Exit the console", 'q', c.app.Stop)
	c.switchTo("main", "Main menu", footerKeys("[yellow::b]Up/Dn[-:-:-]=Move  [yellow::b]Enter[-:-:-]=Select"), list)
}

// ─── register a config ─────────────────────────────────────────────────

func (c *console) showAddConfig() {
	var configStr string
	form := tview.NewForm()
	form.AddInputField("Config string", "", 0, nil, func(t string) { configStr = t })
	form.AddButton("Register", func() {
		body, blockRooted, err := decodeConfigRegistration(configStr)
		if err != nil {
			c.flash("That doesn't look like a config string:\n\n" + err.Error())
			return
		}
		id, err := c.appendConfig(body, blockRooted)
		if err != nil {
			c.flash("Couldn't save:\n\n" + err.Error())
			return
		}
		msg := "Registered.\n\nconfigId:\n" + id + "\n\nMint a share link for it from the main menu."
		if blockRooted {
			msg += "\n\nDevice attestation is REQUIRED: only stock, non-rooted Android\n" +
				"devices (verified boot) will receive it."
		}
		c.flashThen(msg, c.showMain)
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

func (c *console) appendConfig(body json.RawMessage, blockRooted bool) (string, error) {
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
	entry := ConfigEntry{ConfigID: id, Config: body}
	if blockRooted {
		// App "block rooted devices" toggle → strict server-side issuance gate.
		entry.AttestationPolicy = strictDeviceAttestationPolicy()
	}
	list = append(list, entry)
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
			c.showConfigActions(list[row-1].ConfigID)
		}
	})
	c.switchTo("configs", "Configs", footerKeys("[yellow::b]Enter[-:-:-]=Actions"), table)
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
	if redemptionURL == "" {
		redemptionURL = c.deploy().RedeemURL() // derive https://<domain>/v1/redeem
	}
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
	_, link, err := newShareLink(c.state, configID, redemptionURL, redemptions, expiresAt, strings.TrimSpace(label))
	if err != nil {
		return "", err
	}
	return link, nil
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

// ─── server lifecycle ──────────────────────────────────────────────────

func (c *console) showServer() {
	o := c.deploy()
	acmeCacheDir := filepath.Join(c.stateDir, "acme")
	snap := collectLifecycle(c.svc, c.health, c.port, c.cert, o, acmeCacheDir)

	configs, _ := readConfigEntries(filepath.Join(c.stateDir, "configs.json"))
	tokens, _ := loadRedemptionTokensFile(filepath.Join(c.stateDir, "redemption-tokens.json"))
	now := time.Now().UTC()
	live := 0
	for _, t := range tokens {
		if _, code := tokenStatus(*t, now); code == statusLive || code == statusExpiring {
			live++
		}
	}

	var b strings.Builder
	b.WriteString("\n")
	b.WriteString(formatLifecycle(snap, now))
	b.WriteString("\n  [white::b]Your public key[-:-:-]  (recipients pin this automatically — it rides inside every config you hand out; you don't send it separately)\n")
	fmt.Fprintf(&b, "  pubkey     %s\n", c.state.CreatorPubKeyCompressedB64())
	fmt.Fprintf(&b, "  key file   %s  [gray](back this up — losing it breaks everyone)[-]\n", filepath.Join(c.stateDir, "creator-key.pem"))
	fmt.Fprintf(&b, "  registry   %d configs · %d live share links\n", len(configs), live)
	if !snap.Configured {
		b.WriteString("\n  [yellow]Not set up yet — run setup to configure your domain + TLS.[-]\n")
	}
	if !c.canManage {
		fmt.Fprintf(&b,
			"\n  [gray]Service controls need privilege. Re-run with sudo, or:\n"+
				"  sudo %s service <start|stop|restart>[-]\n", defaultBinPath)
	}

	tv := tview.NewTextView().SetDynamicColors(true).SetText(b.String())

	form := tview.NewForm()
	if c.canManage {
		if snap.Svc.Running() {
			form.AddButton("Restart", func() { c.serviceAction("restart") })
			form.AddButton("Stop", func() { c.serviceAction("stop") })
		} else {
			form.AddButton("Start", func() { c.serviceAction("start") })
		}
		form.AddButton("Re-run setup", c.showSetupWizard)
		form.AddButton("Update binary", c.updateBinary)
	}
	form.AddButton("View logs", c.showLogs)
	form.AddButton("Back", c.showMain)
	form.SetButtonsAlign(tview.AlignCenter)

	body := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(tv, 0, 1, false).
		AddItem(form, 3, 0, true)
	c.switchTo("server", "Server", footerKeys("[yellow::b]Tab[-:-:-]=Buttons"), body)
}

// serviceAction runs a privileged systemd verb (start/stop/restart) and
// refreshes the Server screen. It shells `sudo creator-server service <verb>`
// from a goroutine via app.Suspend so sudo's prompt (if any) gets the real TTY
// — never run a privileged shell-out from inside the tview event loop.
func (c *console) serviceAction(verb string) {
	go func() {
		err := c.runServiceVerb(verb)
		c.app.QueueUpdateDraw(func() {
			if err != nil {
				c.flashThen("Couldn't "+verb+" the service:\n\n"+err.Error(), c.showServer)
				return
			}
			c.showServer()
		})
	}()
}

// runServiceVerb executes `creator-server service <verb>` with privilege: as
// root directly, otherwise via sudo (the install.sh sudoers drop-in makes that
// passwordless for this subcommand). app.Suspend hands over the terminal so any
// sudo prompt + systemctl output is visible, then the app resumes.
func (c *console) runServiceVerb(verb string, extraArgs ...string) error {
	var err error
	c.app.Suspend(func() { err = execServiceVerb(verb, extraArgs) })
	return err
}

// execServiceVerb runs `creator-server service <verb>` with privilege (root
// directly, else via sudo). The caller hands over the terminal (app.Suspend);
// this just runs the command, so the setup wizard can chain install + enable in
// a single terminal handover.
func execServiceVerb(verb string, extraArgs []string) error {
	name, args := serviceVerbCommand(os.Geteuid(), selfBinPath(), verb, extraArgs)
	cmd := exec.Command(name, args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	return cmd.Run()
}

// serviceVerbCommand builds the (program, args) for a privileged service verb.
// Pure, so the root-vs-sudo decision and arg shape are unit-tested without
// running anything.
func serviceVerbCommand(euid int, selfPath, verb string, extraArgs []string) (string, []string) {
	base := append([]string{"service", verb}, extraArgs...)
	if euid == 0 {
		return selfPath, base
	}
	return "sudo", append([]string{selfPath}, base...)
}

// selfBinPath returns the path to invoke for privileged re-exec. Prefer the
// canonical install path (which the sudoers drop-in authorizes); fall back to
// the running executable.
func selfBinPath() string {
	if _, err := os.Stat(defaultBinPath); err == nil {
		return defaultBinPath
	}
	if exe, err := os.Executable(); err == nil {
		return exe
	}
	return defaultBinPath
}

// ─── server logs ───────────────────────────────────────────────────────

func (c *console) showLogs() {
	tv := tview.NewTextView().SetScrollable(true).SetWrap(false)
	tv.SetText("Loading logs…")
	tv.SetInputCapture(func(ev *tcell.EventKey) *tcell.EventKey {
		if ev.Rune() == 'r' {
			c.loadLogsInto(tv)
			return nil
		}
		return ev
	})
	c.switchTo("logs", "Server logs", footerKeys("[yellow::b]r[-:-:-]=Refresh  [yellow::b]Up/Dn[-:-:-]=Scroll"), tv)
	c.loadLogsInto(tv)
}

// loadLogsInto fetches the journal tail off the event loop (journalctl can
// block on a slow disk) and writes it back via QueueUpdateDraw.
func (c *console) loadLogsInto(tv *tview.TextView) {
	go func() {
		lines, err := c.svc.Logs(200)
		var text string
		switch {
		case err != nil:
			text = "Couldn't read logs:\n" + err.Error() +
				"\n\n(journalctl may need privilege — try: sudo journalctl -u creator-server)"
		case len(lines) == 0:
			text = "(no log lines yet)"
		default:
			text = strings.Join(lines, "\n")
		}
		c.app.QueueUpdateDraw(func() {
			tv.SetText(text).ScrollToEnd()
		})
	}()
}

// ─── update binary ─────────────────────────────────────────────────────

const installOneLiner = "curl -fsSL https://raw.githubusercontent.com/mukswilly/npvtunnel-creator-server/main/install.sh | sh"

// updateBinary re-runs the signed-release installer (which verifies checksum +
// cosign before replacing the binary), then offers a restart to pick it up.
func (c *console) updateBinary() {
	c.confirm(
		"Update the creator-server binary?\n\n"+
			"This re-runs the official installer (verifies checksum + cosign\n"+
			"signature, then replaces the binary). Your key + configs are untouched.\n"+
			"You'll be offered a restart afterwards.",
		func() {
			go func() {
				var runErr error
				c.app.Suspend(func() {
					cmd := exec.Command("sh", "-c", installOneLiner)
					cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
					runErr = cmd.Run()
				})
				c.app.QueueUpdateDraw(func() {
					if runErr != nil {
						c.flashThen("Update failed:\n\n"+runErr.Error(), c.showServer)
						return
					}
					c.confirm("Updated. Restart the service now to run the new binary?", func() {
						c.serviceAction("restart")
					})
				})
			}()
		})
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
