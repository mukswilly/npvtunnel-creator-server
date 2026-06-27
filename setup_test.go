package main

import (
	"strings"
	"testing"
)

// detectSetupState classifies setup as configured (saved deployment), adopt (unit present but no
// saved deployment), or firstRun (nothing installed).
func TestDetectSetupState(t *testing.T) {
	c, err := newConsole(t.TempDir())
	if err != nil {
		t.Fatalf("newConsole: %v", err)
	}

	c.settings.Deployment = &deployment{SetupComplete: true}
	c.svc = &fakeController{exists: true}
	if got := c.detectSetupState(); got != setupConfigured {
		t.Errorf("SetupComplete → %v, want configured", got)
	}

	c.settings.Deployment = nil
	c.svc = &fakeController{exists: true}
	if got := c.detectSetupState(); got != setupAdopt {
		t.Errorf("unit present, no deployment → %v, want adopt", got)
	}

	c.svc = &fakeController{exists: false}
	if got := c.detectSetupState(); got != setupFirstRun {
		t.Errorf("nothing set up → %v, want firstRun", got)
	}
}

// deploymentFromOpts maps deploy options to the persisted deployment record for both TLS modes.
func TestDeploymentFromOpts(t *testing.T) {
	d := deploymentFromOpts(DeployOpts{Mode: TLSModeBuiltin, Domain: "h", AcmeEmail: "e"})
	if !d.SetupComplete || d.Domain != "h" || d.TLSMode != "builtin" || d.AcmeEmail != "e" {
		t.Errorf("builtin mapping: %+v", d)
	}
	d = deploymentFromOpts(DeployOpts{Mode: TLSModeProxy, Domain: "h", Addr: "127.0.0.1:8443"})
	if d.TLSMode != "proxy" || d.Addr != "127.0.0.1:8443" {
		t.Errorf("proxy mapping: %+v", d)
	}
}

// installArgs builds the service-install argument list, omitting -addr for built-in TLS and
// including -addr/-acme-email where appropriate.
func TestInstallArgs(t *testing.T) {
	joined := strings.Join(installArgs(DeployOpts{
		BinPath: "bin", StateDir: "/s", Mode: TLSModeBuiltin, Domain: "h",
	}), " ")
	for _, want := range []string{"-bin bin", "-state-dir /s", "-tls builtin", "-domain h"} {
		if !strings.Contains(joined, want) {
			t.Errorf("builtin args missing %q: %s", want, joined)
		}
	}
	if strings.Contains(joined, "-addr") {
		t.Errorf("builtin must not pass -addr: %s", joined)
	}

	withEmail := strings.Join(installArgs(DeployOpts{Mode: TLSModeBuiltin, Domain: "h", AcmeEmail: "e@x"}.withDefaults()), " ")
	if !strings.Contains(withEmail, "-acme-email e@x") {
		t.Errorf("missing -acme-email: %s", withEmail)
	}

	proxy := strings.Join(installArgs(DeployOpts{Mode: TLSModeProxy, Domain: "h"}.withDefaults()), " ")
	if !strings.Contains(proxy, "-tls proxy") || !strings.Contains(proxy, "-addr 127.0.0.1:8443") {
		t.Errorf("proxy args: %s", proxy)
	}
}

// setupManualInstructions emits the manual install/enable commands reflecting the chosen options.
func TestSetupManualInstructions(t *testing.T) {
	txt := setupManualInstructions(DeployOpts{
		BinPath: "/usr/local/bin/creator-server", Mode: TLSModeBuiltin, Domain: "h",
	}.withDefaults())
	for _, want := range []string{"service install", "-domain h", "enable-now"} {
		if !strings.Contains(txt, want) {
			t.Errorf("manual instructions missing %q:\n%s", want, txt)
		}
	}
}
