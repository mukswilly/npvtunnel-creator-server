package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// service.go is the on-box server-lifecycle core: the canonical systemd unit
// generator and the pure parsers the management console + the root `service`
// subcommand build on. Everything here is pure (no exec, no root, no systemd)
// so it unit-tests on any OS; the actual systemctl/journalctl shell-outs live
// in the serviceController (added alongside, exercised via a fake in tests).
//
// One canonical unit template lives in renderUnitFile. install.sh shells out to
// `creator-server service install` rather than carrying its own heredoc, and
// the committed systemd/creator-server.service is generated from the same
// function — so the three can't drift (they did before: the committed unit had
// PrivateDevices / ProtectKernelTunables / ProtectControlGroups the installer
// omitted).

const (
	// serviceName is the systemd unit name (creator-server.service).
	serviceName = "creator-server"
	// serviceUnitPath is where the unit is installed. install.sh and the
	// console both write here.
	serviceUnitPath = "/etc/systemd/system/creator-server.service"
	// serviceUser is the unprivileged system account the issuer runs as. The
	// state dir is owned by it; the console must NOT create root-owned state
	// (there is no chown in the tree), which is why the console stays this
	// user and only the `service` subcommand needs root.
	serviceUser = "creator"
	// defaultBinPath is where install.sh places the binary; the unit's
	// ExecStart points here.
	defaultBinPath = "/usr/local/bin/creator-server"
	// defaultProxyAddr is the loopback bind for reverse-proxy mode. The proxy
	// (Caddy/nginx) terminates TLS in front of it.
	defaultProxyAddr = "127.0.0.1:8443"
)

// TLSMode is how HTTPS is terminated for the issuer.
type TLSMode int

const (
	// TLSModeBuiltin: the binary obtains + renews its own Let's Encrypt cert
	// (binds :443, answers ACME on :80, derives -public-issuer-url). Needs
	// CAP_NET_BIND_SERVICE since it runs unprivileged on privileged ports.
	TLSModeBuiltin TLSMode = iota
	// TLSModeProxy: the binary serves plain HTTP on loopback; an external
	// reverse proxy terminates TLS. No privileged ports, no caps.
	TLSModeProxy
)

func (m TLSMode) String() string {
	if m == TLSModeProxy {
		return "proxy"
	}
	return "builtin"
}

// parseTLSMode maps the persisted/flag string back to a TLSMode. Unknown
// values fall back to builtin (the simplest, no-proxy default).
func parseTLSMode(s string) TLSMode {
	if strings.EqualFold(strings.TrimSpace(s), "proxy") {
		return TLSModeProxy
	}
	return TLSModeBuiltin
}

// DeployOpts is everything needed to render a unit and to describe a running
// deployment. It is what the setup wizard collects, what gets persisted in
// console.json, and what the adopt path recovers from an existing unit.
type DeployOpts struct {
	BinPath   string  // path to the creator-server binary (ExecStart program)
	StateDir  string  // -state-dir
	Mode      TLSMode // builtin (Let's Encrypt) | proxy (reverse proxy)
	Domain    string  // public hostname recipients reach
	AcmeEmail string  // optional Let's Encrypt contact (builtin only)
	Addr      string  // proxy-mode bind; default defaultProxyAddr
}

// withDefaults fills the structural defaults so callers (and renderUnitFile)
// don't have to. Domain is intentionally left as-is — it's operator input with
// no sensible default.
func (o DeployOpts) withDefaults() DeployOpts {
	if o.BinPath == "" {
		o.BinPath = defaultBinPath
	}
	if o.StateDir == "" {
		o.StateDir = defaultConsoleStateDir
	}
	if o.Mode == TLSModeProxy && o.Addr == "" {
		o.Addr = defaultProxyAddr
	}
	return o
}

// PublicURL is the https origin recipients hit (no path).
func (o DeployOpts) PublicURL() string {
	if o.Domain == "" {
		return ""
	}
	return "https://" + o.Domain
}

// IssuerURL / RedeemURL derive the per-endpoint URLs from the domain so the
// console never makes a creator retype them (a wrong redemption URL otherwise
// fails silently at the recipient's first connect).
func (o DeployOpts) IssuerURL() string {
	if o.Domain == "" {
		return ""
	}
	return o.PublicURL() + "/v1/issue"
}

func (o DeployOpts) RedeemURL() string {
	if o.Domain == "" {
		return ""
	}
	return o.PublicURL() + "/v1/redeem"
}

// execStartLine builds the single-line ExecStart for the unit. Single-line
// (vs the committed unit's backslash-continued form) keeps it trivial to parse
// back on the adopt path; extractExecStartLine still handles continuations for
// units written by hand or by older installers.
func (o DeployOpts) execStartLine() string {
	o = o.withDefaults()
	switch o.Mode {
	case TLSModeProxy:
		// Loopback HTTP; the proxy supplies the public URL, so the binary
		// needs it told explicitly for /v1/redeem to mint correct envelopes.
		return fmt.Sprintf("%s -addr %s -state-dir %s -public-issuer-url %s",
			o.BinPath, o.Addr, o.StateDir, o.IssuerURL())
	default:
		// Built-in TLS: -domain drives autocert and derives the issuer URL
		// inside main(), so we don't pass -public-issuer-url here.
		line := fmt.Sprintf("%s -state-dir %s -domain %s",
			o.BinPath, o.StateDir, o.Domain)
		if o.AcmeEmail != "" {
			line += " -acme-email " + o.AcmeEmail
		}
		return line
	}
}

// renderUnitFile is the single source of truth for the systemd unit. Both TLS
// modes share the hardening block; only ExecStart and the two capability lines
// differ (built-in TLS binds privileged ports, so it needs
// CAP_NET_BIND_SERVICE — proxy mode leaves both capability sets empty).
func renderUnitFile(o DeployOpts) string {
	o = o.withDefaults()
	capBounding, capAmbient := "", ""
	if o.Mode == TLSModeBuiltin {
		capBounding = "CAP_NET_BIND_SERVICE"
		capAmbient = "CAP_NET_BIND_SERVICE"
	}
	return fmt.Sprintf(`[Unit]
Description=NpvTunnel creator-server (issuer + share-link redemption)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=%s
Group=%s
ExecStart=%s
Restart=on-failure
RestartSec=2

# Hardening — the process only needs to read/write its state dir.
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_INET AF_INET6
ReadWritePaths=%s
CapabilityBoundingSet=%s
AmbientCapabilities=%s

[Install]
WantedBy=multi-user.target
`, serviceUser, serviceUser, o.execStartLine(), o.StateDir, capBounding, capAmbient)
}

// ServiceStatus is the parsed result of `systemctl show creator-server -p ...`.
// Pure data so the lifecycle screen can render it (and tests can fabricate it)
// without a live systemd.
type ServiceStatus struct {
	Loaded      bool      // LoadState == loaded
	Active      bool      // ActiveState == active
	ActiveState string    // active | inactive | failed | activating | ...
	SubState    string    // running | dead | failed | ...
	MainPID     int       // 0 when not running
	Since       time.Time // ActiveEnterTimestamp; zero when unknown/inactive
	Result      string    // success | exit-code | ... (last run result)
}

// Running reports the healthy steady state: active and actually running.
func (s ServiceStatus) Running() bool { return s.Active && s.SubState == "running" }

// Failed reports a crashed/failed unit (so the screen can flag it red).
func (s ServiceStatus) Failed() bool {
	return s.ActiveState == "failed" || s.SubState == "failed"
}

// systemctlShowProps is the property set the controller queries; parsing keys
// off exactly these. Kept next to the parser so the two stay in sync.
var systemctlShowProps = []string{
	"LoadState", "ActiveState", "SubState", "MainPID", "ActiveEnterTimestamp", "Result",
}

// systemdTimestampLayout matches systemd's human ActiveEnterTimestamp, e.g.
// "Wed 2026-06-21 10:03:21 UTC". Parsing is best-effort: an unparseable or
// empty value leaves Since zero (uptime shown as unknown), never an error.
const systemdTimestampLayout = "Mon 2006-01-02 15:04:05 MST"

// parseServiceStatus parses the key=value output of
// `systemctl show creator-server -p <systemctlShowProps...>`. Missing keys are
// tolerated (older systemd, masked unit) — the zero value reads as
// "not loaded / inactive", which is the safe display.
func parseServiceStatus(showOutput string) ServiceStatus {
	kv := map[string]string{}
	for _, line := range strings.Split(showOutput, "\n") {
		line = strings.TrimSpace(line)
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		kv[k] = v
	}
	st := ServiceStatus{
		Loaded:      kv["LoadState"] == "loaded",
		Active:      kv["ActiveState"] == "active",
		ActiveState: kv["ActiveState"],
		SubState:    kv["SubState"],
		Result:      kv["Result"],
	}
	if pid, err := strconv.Atoi(strings.TrimSpace(kv["MainPID"])); err == nil {
		st.MainPID = pid
	}
	if ts := strings.TrimSpace(kv["ActiveEnterTimestamp"]); ts != "" {
		if t, err := time.Parse(systemdTimestampLayout, ts); err == nil {
			st.Since = t
		}
	}
	return st
}

// extractExecStartLine pulls the ExecStart command out of a raw unit file,
// joining systemd's backslash line-continuations and collapsing whitespace.
// Returns "" when there's no ExecStart (e.g. a stub/masked unit). Used by the
// adopt path so a creator who installed via install.sh (and has a unit but no
// console.json) is reconciled instead of re-prompted.
func extractExecStartLine(unitText string) string {
	lines := strings.Split(unitText, "\n")
	for i := 0; i < len(lines); i++ {
		trimmed := strings.TrimSpace(lines[i])
		if !strings.HasPrefix(trimmed, "ExecStart=") {
			continue
		}
		cmd := strings.TrimPrefix(trimmed, "ExecStart=")
		for strings.HasSuffix(strings.TrimSpace(cmd), "\\") {
			cmd = strings.TrimSuffix(strings.TrimSpace(cmd), "\\")
			i++
			if i >= len(lines) {
				break
			}
			cmd += " " + strings.TrimSpace(lines[i])
		}
		return strings.Join(strings.Fields(cmd), " ")
	}
	return ""
}

// parseExecStart recovers DeployOpts from an ExecStart command line (as
// produced by extractExecStartLine). Mode is inferred from the flags present:
// -domain → built-in TLS; -public-issuer-url (no -domain) → reverse proxy.
// Accepts both "-flag value" and "-flag=value" forms.
func parseExecStart(execStart string) DeployOpts {
	fields := normalizeFlagTokens(strings.Fields(execStart))
	var o DeployOpts
	sawDomain := false
	if len(fields) > 0 {
		o.BinPath = fields[0]
	}
	for i := 1; i < len(fields); i++ {
		val := func() string {
			if i+1 < len(fields) {
				i++
				return fields[i]
			}
			return ""
		}
		switch fields[i] {
		case "-domain", "--domain":
			o.Domain = val()
			sawDomain = true
		case "-acme-email", "--acme-email":
			o.AcmeEmail = val()
		case "-state-dir", "--state-dir":
			o.StateDir = val()
		case "-addr", "--addr":
			o.Addr = val()
		case "-public-issuer-url", "--public-issuer-url":
			if o.Domain == "" { // -domain wins if both somehow present
				o.Domain = domainFromURL(val())
			} else {
				val()
			}
		}
	}
	if sawDomain {
		o.Mode = TLSModeBuiltin
	} else {
		o.Mode = TLSModeProxy
	}
	return o.withDefaults()
}

// normalizeFlagTokens splits "-flag=value" tokens into "-flag" "value" so the
// parser only has to handle the space-separated form.
func normalizeFlagTokens(in []string) []string {
	out := make([]string, 0, len(in))
	for _, tok := range in {
		if strings.HasPrefix(tok, "-") {
			if k, v, ok := strings.Cut(tok, "="); ok {
				out = append(out, k, v)
				continue
			}
		}
		out = append(out, tok)
	}
	return out
}

// domainFromURL extracts the bare host from an https URL, dropping scheme and
// any path (e.g. https://issuer.example/v1/issue → issuer.example).
func domainFromURL(u string) string {
	u = strings.TrimPrefix(u, "https://")
	u = strings.TrimPrefix(u, "http://")
	if i := strings.IndexByte(u, '/'); i >= 0 {
		u = u[:i]
	}
	return u
}

// adoptFromUnit recovers DeployOpts from an installed unit file (an install.sh
// user who has a unit but no console.json). Returns ok=false when the file is
// absent or carries no ExecStart.
func adoptFromUnit(unitPath string) (DeployOpts, bool) {
	data, err := os.ReadFile(unitPath)
	if err != nil {
		return DeployOpts{}, false
	}
	line := extractExecStartLine(string(data))
	if line == "" {
		return DeployOpts{}, false
	}
	return parseExecStart(line), true
}

// ─── service control surface ───────────────────────────────────────────
//
// serviceController is the injectable seam between the console / `service`
// subcommand and systemd. The console holds one to render read-only status and
// logs in-process (those work unprivileged); the privileged verbs are reached
// by shelling `sudo creator-server service <verb>`, which builds a real
// systemctlController and calls the same methods as root. Tests use
// fakeController (in service_test.go) so none of this needs root or systemd.
type serviceController interface {
	// UnitExists reports whether the systemd unit file is present (used by the
	// adopt path to recognize an install.sh user).
	UnitExists() bool
	// Install writes the unit file and runs `daemon-reload`. Root-only.
	Install(unit string) error
	// EnableNow runs `systemctl enable --now`. Root-only.
	EnableNow() error
	// Start / Stop / Restart map to the obvious systemctl verbs. Root-only.
	Start() error
	Stop() error
	Restart() error
	// Status parses `systemctl show`. Works unprivileged.
	Status() (ServiceStatus, error)
	// Logs returns the last `lines` journal entries (bounded, non-blocking —
	// never `journalctl -f`, which would freeze the tview event loop).
	Logs(lines int) ([]string, error)
}

// systemctlController is the real serviceController — the one place that shells
// out to systemctl/journalctl. Deliberately thin: it formats args and hands the
// bytes to the pure parsers in this file, so the only CI-untestable surface is
// the exec calls themselves.
type systemctlController struct {
	name     string // unit name, e.g. "creator-server"
	unitPath string // /etc/systemd/system/creator-server.service
}

func newSystemctlController() *systemctlController {
	return &systemctlController{name: serviceName, unitPath: serviceUnitPath}
}

func (c *systemctlController) UnitExists() bool {
	_, err := os.Stat(c.unitPath)
	return err == nil
}

func (c *systemctlController) Install(unit string) error {
	// Units carry no secrets; 0644 (world-readable) matches systemd convention
	// and what install.sh produced. NOTE: this writes ONLY the unit file — it
	// never touches the state dir, so a root-run `service install` can't leave
	// root-owned state the creator-user service then can't read.
	if err := os.WriteFile(c.unitPath, []byte(unit), 0o644); err != nil {
		return fmt.Errorf("write unit %s: %w", c.unitPath, err)
	}
	// daemon-reload BEFORE any enable/start so systemd sees the new unit.
	return c.run("daemon-reload")
}

func (c *systemctlController) EnableNow() error { return c.run("enable", "--now", c.name) }
func (c *systemctlController) Start() error     { return c.run("start", c.name) }
func (c *systemctlController) Stop() error      { return c.run("stop", c.name) }
func (c *systemctlController) Restart() error   { return c.run("restart", c.name) }

// run executes `systemctl <args...>` and folds stderr into the error so a
// failure (e.g. "must be root") surfaces a usable message.
func (c *systemctlController) run(args ...string) error {
	out, err := exec.Command("systemctl", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl %s: %w: %s",
			strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (c *systemctlController) Status() (ServiceStatus, error) {
	// `systemctl show` exits 0 even for unknown units (it prints defaults), so
	// a non-nil error here is a real failure (systemctl absent, not systemd).
	out, err := exec.Command("systemctl", "show", c.name,
		"--property="+strings.Join(systemctlShowProps, ",")).Output()
	if err != nil {
		return ServiceStatus{}, fmt.Errorf("systemctl show %s: %w", c.name, err)
	}
	return parseServiceStatus(string(out)), nil
}

func (c *systemctlController) Logs(lines int) ([]string, error) {
	if lines <= 0 {
		lines = 100
	}
	// -o cat: message only (no timestamp/host noise); --no-pager + -n N: a
	// bounded tail that returns immediately. NEVER -f.
	out, err := exec.Command("journalctl", "-u", c.name,
		"-n", strconv.Itoa(lines), "--no-pager", "-o", "cat").CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("journalctl -u %s: %w: %s",
			c.name, err, strings.TrimSpace(string(out)))
	}
	trimmed := strings.TrimRight(string(out), "\n")
	if trimmed == "" {
		return nil, nil
	}
	return strings.Split(trimmed, "\n"), nil
}

var _ serviceController = (*systemctlController)(nil)

// ─── privilege detection ───────────────────────────────────────────────

// canManageSystemd reports whether this process can run the privileged service
// verbs — either it's already root, or `sudo -n` works without a password
// prompt (cached creds / NOPASSWD). On non-Linux (the Windows dev box) both are
// false, which is correct: server management is Linux-only. This is an exec
// seam; the console caches the result once at construction.
func canManageSystemd() bool {
	if os.Geteuid() == 0 {
		return true
	}
	return sudoNonInteractiveOK()
}

// sudoNonInteractiveOK probes whether sudo can elevate WITHOUT prompting (so we
// never fire a password prompt from inside the tview event loop). A prompt is
// still possible interactively via app.Suspend; this only decides whether the
// action is offered as live vs. read-only.
func sudoNonInteractiveOK() bool {
	if _, err := exec.LookPath("sudo"); err != nil {
		return false
	}
	return exec.Command("sudo", "-n", "true").Run() == nil
}

// ─── `creator-server service <verb>` subcommand ────────────────────────

// runServiceSubcommand handles `creator-server service <verb> [flags]` — the
// root-only management entrypoint the console shells into via sudo (and that
// install.sh calls to write the unit, so unit generation has ONE home). Verbs:
// install | enable-now | start | stop | restart | status | logs.
func runServiceSubcommand(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr,
			"service: expected a verb: install | enable-now | start | stop | restart | status | logs")
		return 2
	}
	verb := args[0]
	fs := flag.NewFlagSet("service "+verb, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	stateDir := fs.String("state-dir", defaultConsoleStateDir, "state directory (-state-dir passed to the server)")
	tlsMode := fs.String("tls", "builtin", "TLS mode for `install`: builtin (Let's Encrypt) | proxy (reverse proxy)")
	domain := fs.String("domain", "", "public hostname for `install`")
	acmeEmail := fs.String("acme-email", "", "Let's Encrypt contact email (builtin TLS)")
	addr := fs.String("addr", defaultProxyAddr, "loopback bind for proxy mode `install`")
	binPath := fs.String("bin", defaultBinPath, "path to the creator-server binary for ExecStart")
	logLines := fs.Int("n", 100, "number of log lines for `logs`")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}

	opts := DeployOpts{
		BinPath:   *binPath,
		StateDir:  *stateDir,
		Mode:      parseTLSMode(*tlsMode),
		Domain:    *domain,
		AcmeEmail: *acmeEmail,
		Addr:      *addr,
	}
	if verb == "install" && opts.Domain == "" {
		fmt.Fprintln(os.Stderr, "service install: -domain is required")
		return 2
	}

	ctrl := newSystemctlController()
	if err := dispatchServiceVerb(ctrl, verb, opts, *logLines, os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "service %s: %v\n", verb, err)
		return 1
	}
	return 0
}

// dispatchServiceVerb is the testable core of the subcommand: it maps a verb to
// a serviceController call (and renders the unit for `install`). Pure routing —
// fakeController-driven tests cover every branch with no systemd.
func dispatchServiceVerb(ctrl serviceController, verb string, opts DeployOpts, logLines int, out io.Writer) error {
	switch verb {
	case "install":
		if err := ctrl.Install(renderUnitFile(opts)); err != nil {
			return err
		}
		fmt.Fprintf(out, "installed unit at %s (%s TLS)\n", serviceUnitPath, opts.Mode)
		return nil
	case "enable-now":
		return ctrl.EnableNow()
	case "start":
		return ctrl.Start()
	case "stop":
		return ctrl.Stop()
	case "restart":
		return ctrl.Restart()
	case "status":
		st, err := ctrl.Status()
		if err != nil {
			return err
		}
		fmt.Fprintln(out, formatServiceStatusLine(st))
		return nil
	case "logs":
		lines, err := ctrl.Logs(logLines)
		if err != nil {
			return err
		}
		for _, l := range lines {
			fmt.Fprintln(out, l)
		}
		return nil
	default:
		return fmt.Errorf("unknown verb %q (want install|enable-now|start|stop|restart|status|logs)", verb)
	}
}

// formatServiceStatusLine renders a one-line human status, e.g.
// "active (running) since 2026-06-21T10:03:21Z pid 1234" or "inactive (dead)".
func formatServiceStatusLine(s ServiceStatus) string {
	state := s.ActiveState
	if state == "" {
		state = "unknown"
	}
	line := state
	if s.SubState != "" {
		line += " (" + s.SubState + ")"
	}
	if s.Running() && !s.Since.IsZero() {
		line += " since " + s.Since.UTC().Format(time.RFC3339)
	}
	if s.MainPID > 0 {
		line += fmt.Sprintf(" pid %d", s.MainPID)
	}
	return line
}
