package main

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

// setup.go is the first-run / re-run setup flow: collect domain + TLS mode,
// write + enable the systemd unit (via the privileged `service` subcommand),
// wait for /healthz, and gate on backing up the key. It also owns the
// first-run-vs-steady-state decision and the adopt path that reconciles an
// install.sh user (a unit but no console.json) without re-prompting.

type setupState int

const (
	setupFirstRun   setupState = iota // no deployment, no unit → run the wizard
	setupAdopt                        // unit exists but unconfigured → reconcile
	setupConfigured                   // deployment recorded → straight to the menu
)

// detectSetupState decides what the console should open on. The persisted
// SetupComplete flag is authoritative; an existing unit (install.sh user) is
// the corroborating signal that lets us adopt rather than re-prompt.
func (c *console) detectSetupState() setupState {
	if d := c.settings.Deployment; d != nil && d.SetupComplete {
		return setupConfigured
	}
	if c.svc.UnitExists() {
		return setupAdopt
	}
	return setupFirstRun
}

// adoptDeployment backfills the persisted deployment from an already-installed
// unit so an install.sh user is never dropped into the wizard.
func (c *console) adoptDeployment() {
	o, ok := adoptFromUnit(serviceUnitPath)
	if !ok {
		return
	}
	o.StateDir = c.stateDir
	c.settings.Deployment = deploymentFromOpts(o.withDefaults())
	c.saveSettings()
}

// deploymentFromOpts is the pure mapping DeployOpts → persisted deployment.
func deploymentFromOpts(o DeployOpts) *deployment {
	return &deployment{
		SetupComplete: true,
		Domain:        o.Domain,
		TLSMode:       o.Mode.String(),
		Addr:          o.Addr,
		AcmeEmail:     o.AcmeEmail,
	}
}

// ─── the wizard ────────────────────────────────────────────────────────

func (c *console) showSetupWizard() {
	cur := c.deploy() // prefill from current/adopted deployment (re-run case)
	domain := cur.Domain
	mode := cur.Mode
	email := cur.AcmeEmail

	form := tview.NewForm()
	form.AddInputField("Public hostname", domain, 40, nil, func(t string) { domain = t })
	form.AddDropDown("HTTPS",
		[]string{"This binary, via Let's Encrypt", "A reverse proxy I run"},
		int(mode), func(_ string, idx int) { mode = TLSMode(idx) })
	form.AddInputField("Let's Encrypt email (optional)", email, 40, nil, func(t string) { email = t })
	form.AddButton("Set up", func() {
		c.applySetup(strings.TrimSpace(domain), mode, strings.TrimSpace(email))
	})
	form.AddButton("Cancel", c.showMain)
	form.SetBorder(true).SetTitle(" Set up this server ")

	help := tview.NewTextView().SetDynamicColors(true).SetText(
		"\n  The hostname is what recipients' apps reach — point its DNS A record\n" +
			"  at this server.\n\n" +
			"  • Built-in Let's Encrypt: simplest, needs ports 80+443 open.\n" +
			"  • Reverse proxy: serves http://127.0.0.1:8443 for a Caddy/nginx you run.")
	help.SetTextColor(tcell.ColorGray)

	body := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(form, 0, 1, true).
		AddItem(help, 6, 0, false)
	c.switchTo("setup", "Set up this server", footerKeys(""), body)
}

// applySetup validates the inputs, writes + enables the unit (privileged), then
// waits for health. When the console can't manage systemd, it degrades to
// showing the exact commands to run.
func (c *console) applySetup(domain string, mode TLSMode, email string) {
	if domain == "" {
		c.flash("Public hostname is required.")
		return
	}
	if strings.ContainsAny(domain, "/: ") {
		c.flash("Hostname must be a bare host — no scheme, port, or path.\n\nGot: " + domain)
		return
	}
	opts := DeployOpts{
		BinPath:   selfBinPath(),
		StateDir:  c.stateDir,
		Mode:      mode,
		Domain:    domain,
		AcmeEmail: email,
	}.withDefaults()

	if !c.canManage {
		c.flash(setupManualInstructions(opts))
		return
	}

	go func() {
		err := c.runSetupCommands(installArgs(opts))
		c.app.QueueUpdateDraw(func() {
			if err != nil {
				c.flashThen("Setup failed:\n\n"+err.Error(), c.showSetupWizard)
				return
			}
			// Persist only after the unit is installed + enabled.
			c.settings.Deployment = deploymentFromOpts(opts)
			c.saveSettings()
			c.pollHealthThenFinish(opts)
		})
	}()
}

// runSetupCommands installs the unit then enables+starts it, in a single
// app.Suspend so the terminal is handed over once for both (one sudo prompt at
// most, both commands' output visible).
func (c *console) runSetupCommands(args []string) error {
	var err error
	c.app.Suspend(func() {
		if err = execServiceVerb("install", args); err != nil {
			return
		}
		err = execServiceVerb("enable-now", nil)
	})
	return err
}

// installArgs is the pure flag list for `service install` from a deployment.
func installArgs(o DeployOpts) []string {
	args := []string{
		"-bin", o.BinPath,
		"-state-dir", o.StateDir,
		"-tls", o.Mode.String(),
		"-domain", o.Domain,
	}
	if o.Mode == TLSModeProxy {
		args = append(args, "-addr", o.Addr)
	}
	if o.AcmeEmail != "" {
		args = append(args, "-acme-email", o.AcmeEmail)
	}
	return args
}

// setupManualInstructions is the copyable fallback when the console lacks the
// privilege to manage systemd itself.
func setupManualInstructions(o DeployOpts) string {
	return fmt.Sprintf(
		"This console can't manage systemd here (not root, and sudo isn't\n"+
			"available passwordless). Run these as root to finish:\n\n"+
			"  sudo %s service install %s\n"+
			"  sudo %s service enable-now\n",
		o.BinPath, strings.Join(installArgs(o), " "), o.BinPath)
}

// pollHealthThenFinish waits (in the background) for the service to answer
// /healthz, showing progress, then lands on the finish screen. Built-in TLS can
// take a minute to obtain its first cert, so a timeout isn't treated as failure
// — just "not answering yet".
func (c *console) pollHealthThenFinish(opts DeployOpts) {
	url := healthURL(opts)
	tv := tview.NewTextView().SetDynamicColors(true).
		SetText("\n  Starting the service and waiting for it to answer…")
	c.switchTo("setupwait", "Set up this server", footerKeys(""), tv)

	go func() {
		const deadline = 45 * time.Second
		const interval = 3 * time.Second
		healthy := false
		for waited := time.Duration(0); waited <= deadline; waited += interval {
			if ok, _ := c.health.Healthz(url); ok {
				healthy = true
				break
			}
			elapsed := waited + interval
			c.app.QueueUpdateDraw(func() {
				tv.SetText(fmt.Sprintf(
					"\n  Starting the service and waiting for HTTPS…  (%ds)\n\n  %s",
					int(elapsed.Seconds()), url))
			})
			time.Sleep(interval)
		}
		c.app.QueueUpdateDraw(func() { c.finishSetup(opts, healthy) })
	}()
}

// finishSetup is the terminal wizard screen: health result + the all-important
// back-up-your-key gate.
func (c *console) finishSetup(opts DeployOpts, healthy bool) {
	status := "[green]The service is up and answering on " + healthURL(opts) + ".[-]"
	if !healthy {
		status = "[yellow]Installed and started, but it hasn't answered yet.\n" +
			"  Built-in TLS can take a minute to get its first certificate —\n" +
			"  check the Server screen or logs shortly.[-]"
	}
	msg := fmt.Sprintf(
		"\n  %s\n\n"+
			"  [white::b]Your creator identity[-:-:-]\n"+
			"  pubkey    %s\n"+
			"  key file  %s\n\n"+
			"  [red::b]BACK THIS UP NOW[-:-:-] — lose the key and every recipient breaks.\n",
		status, c.state.CreatorPubKeyCompressedB64(),
		filepath.Join(c.stateDir, "creator-key.pem"))

	tv := tview.NewTextView().SetDynamicColors(true).SetText(msg)
	form := tview.NewForm()
	form.AddButton("Back up now", c.showBackup)
	form.AddButton("Go to Server", c.showServer)
	form.AddButton("Main menu", c.showMain)
	form.SetButtonsAlign(tview.AlignCenter)

	body := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(tv, 0, 1, false).
		AddItem(form, 3, 0, true)
	c.switchTo("setupdone", "Setup complete", footerKeys(""), body)
}
