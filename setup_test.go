package main

import (
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
