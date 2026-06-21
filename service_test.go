package main

import (
	"bytes"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
)

// fakeController is a serviceController test double: it records the verbs it was
// asked to run, captures the installed unit, and can be scripted with a status,
// logs, or a per-verb error. Shared by service + screen tests so neither needs
// root or a live systemd.
type fakeController struct {
	exists        bool
	status        ServiceStatus
	statusErr     error
	logs          []string
	logsErr       error
	calls         []string
	installedUnit string
	failOn        map[string]error
}

func (f *fakeController) rec(v string) error {
	f.calls = append(f.calls, v)
	if err, ok := f.failOn[v]; ok {
		return err
	}
	return nil
}

func (f *fakeController) UnitExists() bool               { return f.exists }
func (f *fakeController) Install(unit string) error      { f.installedUnit = unit; return f.rec("install") }
func (f *fakeController) EnableNow() error               { return f.rec("enable-now") }
func (f *fakeController) Start() error                   { return f.rec("start") }
func (f *fakeController) Stop() error                    { return f.rec("stop") }
func (f *fakeController) Restart() error                 { return f.rec("restart") }
func (f *fakeController) Status() (ServiceStatus, error) { return f.status, f.statusErr }
func (f *fakeController) Logs(int) ([]string, error)     { return f.logs, f.logsErr }

// The hardening directives every rendered unit must carry, regardless of TLS
// mode. These are the stricter committed-unit set the installer used to omit;
// the golden test guards against silent drift if someone edits renderUnitFile.
var requiredUnitDirectives = []string{
	"User=creator",
	"Group=creator",
	"NoNewPrivileges=true",
	"ProtectSystem=strict",
	"ProtectHome=true",
	"PrivateTmp=true",
	"PrivateDevices=true",
	"ProtectKernelTunables=true",
	"ProtectControlGroups=true",
	"RestrictAddressFamilies=AF_INET AF_INET6",
	"WantedBy=multi-user.target",
}

func TestRenderUnitFileBuiltin(t *testing.T) {
	unit := renderUnitFile(DeployOpts{
		Mode:      TLSModeBuiltin,
		Domain:    "issuer.alpha.example",
		AcmeEmail: "me@alpha.example",
	})
	for _, want := range requiredUnitDirectives {
		if !strings.Contains(unit, want) {
			t.Errorf("built-in unit missing directive %q\n---\n%s", want, unit)
		}
	}
	// Built-in TLS binds privileged ports, so it MUST grant the bind cap.
	if !strings.Contains(unit, "CapabilityBoundingSet=CAP_NET_BIND_SERVICE") ||
		!strings.Contains(unit, "AmbientCapabilities=CAP_NET_BIND_SERVICE") {
		t.Errorf("built-in unit must grant CAP_NET_BIND_SERVICE\n---\n%s", unit)
	}
	// ExecStart shape: -domain + -acme-email, defaults filled, no proxy flags.
	if !strings.Contains(unit, "-domain issuer.alpha.example") {
		t.Errorf("built-in ExecStart missing -domain\n---\n%s", unit)
	}
	if !strings.Contains(unit, "-acme-email me@alpha.example") {
		t.Errorf("built-in ExecStart missing -acme-email\n---\n%s", unit)
	}
	if !strings.Contains(unit, "-state-dir "+defaultConsoleStateDir) {
		t.Errorf("built-in ExecStart missing default state dir\n---\n%s", unit)
	}
	if strings.Contains(unit, "-public-issuer-url") {
		t.Errorf("built-in ExecStart should not set -public-issuer-url (derived from -domain)\n---\n%s", unit)
	}
}

func TestRenderUnitFileProxy(t *testing.T) {
	unit := renderUnitFile(DeployOpts{
		Mode:   TLSModeProxy,
		Domain: "issuer.alpha.example",
	})
	for _, want := range requiredUnitDirectives {
		if !strings.Contains(unit, want) {
			t.Errorf("proxy unit missing directive %q\n---\n%s", want, unit)
		}
	}
	// Proxy mode binds only loopback: capabilities must be EMPTY.
	if !strings.Contains(unit, "CapabilityBoundingSet=\n") ||
		!strings.Contains(unit, "AmbientCapabilities=\n") {
		t.Errorf("proxy unit must leave capability sets empty\n---\n%s", unit)
	}
	if strings.Contains(unit, "CAP_NET_BIND_SERVICE") {
		t.Errorf("proxy unit must not grant CAP_NET_BIND_SERVICE\n---\n%s", unit)
	}
	if !strings.Contains(unit, "-addr "+defaultProxyAddr) {
		t.Errorf("proxy ExecStart missing -addr %s\n---\n%s", defaultProxyAddr, unit)
	}
	if !strings.Contains(unit, "-public-issuer-url https://issuer.alpha.example/v1/issue") {
		t.Errorf("proxy ExecStart missing derived -public-issuer-url\n---\n%s", unit)
	}
	// No CHANGE_ME placeholder ever — that was the old install.sh footgun.
	if strings.Contains(unit, "CHANGE_ME") {
		t.Errorf("proxy unit must not contain a CHANGE_ME placeholder\n---\n%s", unit)
	}
}

func TestDeployOptsDerivedURLs(t *testing.T) {
	o := DeployOpts{Domain: "issuer.alpha.example"}
	if got := o.IssuerURL(); got != "https://issuer.alpha.example/v1/issue" {
		t.Errorf("IssuerURL = %q", got)
	}
	if got := o.RedeemURL(); got != "https://issuer.alpha.example/v1/redeem" {
		t.Errorf("RedeemURL = %q", got)
	}
	if got := (DeployOpts{}).IssuerURL(); got != "" {
		t.Errorf("IssuerURL with no domain = %q, want empty", got)
	}
}

func TestParseServiceStatus(t *testing.T) {
	tests := []struct {
		name    string
		show    string
		running bool
		failed  bool
		pid     int
		active  string
		hasTime bool
	}{
		{
			name: "active running",
			show: "LoadState=loaded\nActiveState=active\nSubState=running\n" +
				"MainPID=1234\nActiveEnterTimestamp=Wed 2026-06-21 10:03:21 UTC\nResult=success\n",
			running: true, failed: false, pid: 1234, active: "active", hasTime: true,
		},
		{
			name:   "failed",
			show:   "LoadState=loaded\nActiveState=failed\nSubState=failed\nMainPID=0\nResult=exit-code\n",
			failed: true, pid: 0, active: "failed",
		},
		{
			name:   "inactive",
			show:   "LoadState=loaded\nActiveState=inactive\nSubState=dead\nMainPID=0\n",
			active: "inactive",
		},
		{
			name: "not loaded / missing keys",
			show: "LoadState=not-found\n",
		},
		{
			name:    "bad timestamp leaves zero",
			show:    "ActiveState=active\nSubState=running\nActiveEnterTimestamp=garbage\n",
			running: true, active: "active", hasTime: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			st := parseServiceStatus(tt.show)
			if st.Running() != tt.running {
				t.Errorf("Running() = %v, want %v", st.Running(), tt.running)
			}
			if st.Failed() != tt.failed {
				t.Errorf("Failed() = %v, want %v", st.Failed(), tt.failed)
			}
			if st.MainPID != tt.pid {
				t.Errorf("MainPID = %d, want %d", st.MainPID, tt.pid)
			}
			if tt.active != "" && st.ActiveState != tt.active {
				t.Errorf("ActiveState = %q, want %q", st.ActiveState, tt.active)
			}
			if st.Since.IsZero() == tt.hasTime {
				t.Errorf("Since.IsZero() = %v, want hasTime=%v", st.Since.IsZero(), tt.hasTime)
			}
		})
	}
}

func TestExtractExecStartLine(t *testing.T) {
	tests := []struct {
		name string
		unit string
		want string
	}{
		{
			name: "single line",
			unit: "[Service]\nExecStart=/usr/local/bin/creator-server -state-dir /s -domain h\nRestart=on-failure\n",
			want: "/usr/local/bin/creator-server -state-dir /s -domain h",
		},
		{
			name: "backslash continuations (committed-unit form)",
			unit: "[Service]\nExecStart=/usr/local/bin/creator-server \\\n" +
				"  -addr 127.0.0.1:8443 \\\n" +
				"  -state-dir /var/lib/creator-server \\\n" +
				"  -public-issuer-url https://CHANGE_ME.example/v1/issue\nRestart=on-failure\n",
			want: "/usr/local/bin/creator-server -addr 127.0.0.1:8443 -state-dir /var/lib/creator-server -public-issuer-url https://CHANGE_ME.example/v1/issue",
		},
		{
			name: "no ExecStart",
			unit: "[Unit]\nDescription=x\n",
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := extractExecStartLine(tt.unit); got != tt.want {
				t.Errorf("extractExecStartLine = %q\nwant %q", got, tt.want)
			}
		})
	}
}

// TestExecStartRoundTrip renders a unit, pulls ExecStart back out, parses it,
// and asserts the DeployOpts survive — this is exactly the adopt path
// (install.sh user with a unit but no console.json).
func TestExecStartRoundTrip(t *testing.T) {
	cases := []DeployOpts{
		{Mode: TLSModeBuiltin, Domain: "issuer.alpha.example", AcmeEmail: "me@alpha.example"},
		{Mode: TLSModeBuiltin, Domain: "issuer.beta.example"}, // no email
		{Mode: TLSModeProxy, Domain: "issuer.gamma.example"},
	}
	for _, in := range cases {
		in = in.withDefaults()
		unit := renderUnitFile(in)
		got := parseExecStart(extractExecStartLine(unit))
		if got.Mode != in.Mode {
			t.Errorf("%s: Mode = %v, want %v", in.Domain, got.Mode, in.Mode)
		}
		if got.Domain != in.Domain {
			t.Errorf("%s: Domain = %q, want %q", in.Domain, got.Domain, in.Domain)
		}
		if got.StateDir != in.StateDir {
			t.Errorf("%s: StateDir = %q, want %q", in.Domain, got.StateDir, in.StateDir)
		}
		if got.AcmeEmail != in.AcmeEmail {
			t.Errorf("%s: AcmeEmail = %q, want %q", in.Domain, got.AcmeEmail, in.AcmeEmail)
		}
		if in.Mode == TLSModeProxy && got.Addr != in.Addr {
			t.Errorf("%s: Addr = %q, want %q", in.Domain, got.Addr, in.Addr)
		}
	}
}

func TestParseExecStartEqualsForm(t *testing.T) {
	// Go's flag package also accepts -flag=value; parseExecStart must too.
	got := parseExecStart("/usr/local/bin/creator-server -state-dir=/s -domain=h.example -acme-email=a@b.c")
	if got.Mode != TLSModeBuiltin || got.Domain != "h.example" ||
		got.StateDir != "/s" || got.AcmeEmail != "a@b.c" {
		t.Errorf("equals-form parse wrong: %+v", got)
	}
}

func TestDispatchServiceVerbInstall(t *testing.T) {
	f := &fakeController{}
	var buf bytes.Buffer
	opts := DeployOpts{Mode: TLSModeBuiltin, Domain: "issuer.x.example"}
	if err := dispatchServiceVerb(f, "install", opts, 0, &buf); err != nil {
		t.Fatalf("install: %v", err)
	}
	if len(f.calls) != 1 || f.calls[0] != "install" {
		t.Errorf("calls = %v, want [install]", f.calls)
	}
	// The unit handed to Install must be the one renderUnitFile produced.
	if !strings.Contains(f.installedUnit, "-domain issuer.x.example") ||
		!strings.Contains(f.installedUnit, "ProtectSystem=strict") {
		t.Errorf("installed unit not from renderUnitFile:\n%s", f.installedUnit)
	}
	if !strings.Contains(buf.String(), serviceUnitPath) {
		t.Errorf("install output missing unit path: %q", buf.String())
	}
}

func TestDispatchServiceVerbActions(t *testing.T) {
	for _, verb := range []string{"start", "stop", "restart", "enable-now"} {
		f := &fakeController{}
		if err := dispatchServiceVerb(f, verb, DeployOpts{}, 0, io.Discard); err != nil {
			t.Fatalf("%s: %v", verb, err)
		}
		if len(f.calls) != 1 || f.calls[0] != verb {
			t.Errorf("%s: calls = %v", verb, f.calls)
		}
	}
}

func TestDispatchServiceVerbStatus(t *testing.T) {
	f := &fakeController{status: ServiceStatus{
		Active: true, ActiveState: "active", SubState: "running", MainPID: 42,
	}}
	var buf bytes.Buffer
	if err := dispatchServiceVerb(f, "status", DeployOpts{}, 0, &buf); err != nil {
		t.Fatalf("status: %v", err)
	}
	if !strings.Contains(buf.String(), "active (running)") || !strings.Contains(buf.String(), "pid 42") {
		t.Errorf("status output = %q", buf.String())
	}
}

func TestDispatchServiceVerbLogs(t *testing.T) {
	f := &fakeController{logs: []string{"line1", "line2"}}
	var buf bytes.Buffer
	if err := dispatchServiceVerb(f, "logs", DeployOpts{}, 50, &buf); err != nil {
		t.Fatalf("logs: %v", err)
	}
	if buf.String() != "line1\nline2\n" {
		t.Errorf("logs output = %q", buf.String())
	}
}

func TestDispatchServiceVerbErrors(t *testing.T) {
	f := &fakeController{failOn: map[string]error{"start": errors.New("boom")}}
	if err := dispatchServiceVerb(f, "start", DeployOpts{}, 0, io.Discard); err == nil {
		t.Error("expected Start error to propagate")
	}
	if err := dispatchServiceVerb(&fakeController{}, "bogus", DeployOpts{}, 0, io.Discard); err == nil {
		t.Error("expected error for unknown verb")
	}
}

// TestCommittedReferenceUnitMatchesGenerator pins the committed reference unit
// to renderUnitFile's output (proxy mode, CHANGE_ME placeholder) so the file,
// install.sh, and the console can never drift apart again — the exact bug this
// slice fixed.
func TestCommittedReferenceUnitMatchesGenerator(t *testing.T) {
	data, err := os.ReadFile("systemd/creator-server.service")
	if err != nil {
		t.Fatalf("read reference unit: %v", err)
	}
	text := string(data)
	idx := strings.Index(text, "[Unit]")
	if idx < 0 {
		t.Fatal("reference unit missing [Unit] section")
	}
	got := text[idx:]
	want := renderUnitFile(DeployOpts{Mode: TLSModeProxy, Domain: "CHANGE_ME.example"})
	if got != want {
		t.Errorf("committed reference unit drifted from renderUnitFile.\n--- committed ---\n%s\n--- generator ---\n%s", got, want)
	}
}
