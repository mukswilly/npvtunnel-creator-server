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

const (
	// serviceName is the systemd unit name used by all systemctl/journalctl calls.
	serviceName = "creator-server"

	// serviceUnitPath is the on-disk location of the installed systemd unit file.
	serviceUnitPath = "/etc/systemd/system/creator-server.service"

	// serviceUser is the unprivileged account the unit runs the server as.
	serviceUser = "creator"

	// defaultBinPath is the assumed install location of the server binary used in ExecStart.
	defaultBinPath = "/usr/local/bin/creator-server"

	// defaultProxyAddr is the loopback bind address used in proxy TLS mode, where an
	// external reverse proxy terminates TLS and forwards to this address.
	defaultProxyAddr = "127.0.0.1:8443"
)

// TLSMode selects how the deployed server obtains and terminates TLS.
type TLSMode int

const (
	// TLSModeBuiltin has the server obtain certificates directly via Let's Encrypt
	// and bind the public HTTPS port itself.
	TLSModeBuiltin TLSMode = iota

	// TLSModeProxy has the server listen in plaintext on a loopback address while an
	// external reverse proxy terminates TLS and forwards requests to it.
	TLSModeProxy
)

// String returns the lowercase mode name ("builtin" or "proxy").
func (m TLSMode) String() string {
	if m == TLSModeProxy {
		return "proxy"
	}
	return "builtin"
}

// parseTLSMode maps a mode string to a TLSMode, defaulting to builtin for any
// value other than "proxy" (case-insensitive).
func parseTLSMode(s string) TLSMode {
	if strings.EqualFold(strings.TrimSpace(s), "proxy") {
		return TLSModeProxy
	}
	return TLSModeBuiltin
}

// DeployOpts captures the inputs needed to render and install the systemd unit.
type DeployOpts struct {
	BinPath   string  // path to the server binary used in ExecStart
	StateDir  string  // server state directory (-state-dir)
	Mode      TLSMode // TLS termination strategy
	Domain    string  // public hostname for builtin TLS and derived URLs
	AcmeEmail string  // optional Let's Encrypt contact email (builtin TLS)
	Addr      string  // loopback bind address (proxy mode)
}

// withDefaults returns a copy of o with empty fields filled from package defaults.
// The proxy bind address is only defaulted in proxy mode.
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

// PublicURL returns the https base URL for the configured domain, or "" if unset.
func (o DeployOpts) PublicURL() string {
	if o.Domain == "" {
		return ""
	}
	return "https://" + o.Domain
}

// IssuerURL returns the public URL of the issue endpoint, or "" if no domain is set.
func (o DeployOpts) IssuerURL() string {
	if o.Domain == "" {
		return ""
	}
	return o.PublicURL() + "/v1/issue"
}

// RedeemURL returns the public URL of the redeem endpoint, or "" if no domain is set.
func (o DeployOpts) RedeemURL() string {
	if o.Domain == "" {
		return ""
	}
	return o.PublicURL() + "/v1/redeem"
}

// execStartLine builds the ExecStart command line for the unit, with flags that
// depend on the TLS mode.
func (o DeployOpts) execStartLine() string {
	o = o.withDefaults()
	switch o.Mode {
	case TLSModeProxy:
		// Plaintext loopback listener plus the externally reachable issuer URL so
		// issued payloads advertise the public address fronted by the proxy.
		return fmt.Sprintf("%s -addr %s -state-dir %s -public-issuer-url %s",
			o.BinPath, o.Addr, o.StateDir, o.IssuerURL())
	default:
		// Builtin TLS: the server manages certificates for the given domain itself.
		line := fmt.Sprintf("%s -state-dir %s -domain %s",
			o.BinPath, o.StateDir, o.Domain)
		if o.AcmeEmail != "" {
			line += " -acme-email " + o.AcmeEmail
		}
		return line
	}
}

// renderUnitFile produces the full text of the systemd unit for the given options.
// In builtin TLS mode the unprivileged service must bind a privileged port, so it
// is granted CAP_NET_BIND_SERVICE; in proxy mode it binds only a high loopback
// port and needs no extra capabilities.
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

// ServiceStatus is a parsed snapshot of a unit's runtime state, distilled from
// the properties reported by "systemctl show".
type ServiceStatus struct {
	Loaded      bool      // unit file is loaded (LoadState == "loaded")
	Active      bool      // unit is active (ActiveState == "active")
	ActiveState string    // raw ActiveState (e.g. "active", "failed", "inactive")
	SubState    string    // raw SubState (e.g. "running", "dead", "failed")
	MainPID     int       // PID of the main process, 0 if none
	Since       time.Time // time the unit entered the active state
	Result      string    // last exit result (e.g. "success", "exit-code")
}

// Running reports whether the unit is active and its main process is running.
func (s ServiceStatus) Running() bool { return s.Active && s.SubState == "running" }

// Failed reports whether the unit is in a failed active- or sub-state.
func (s ServiceStatus) Failed() bool {
	return s.ActiveState == "failed" || s.SubState == "failed"
}

// systemctlShowProps lists the unit properties requested from "systemctl show".
var systemctlShowProps = []string{
	"LoadState", "ActiveState", "SubState", "MainPID", "ActiveEnterTimestamp", "Result",
}

// systemdTimestampLayout is the time.Parse layout for systemd's timestamp format.
const systemdTimestampLayout = "Mon 2006-01-02 15:04:05 MST"

// parseServiceStatus parses the KEY=VALUE lines emitted by "systemctl show" into
// a ServiceStatus, ignoring lines that lack an "=" separator.
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

// extractExecStartLine returns the ExecStart command from unit text as a single
// space-collapsed line, joining backslash line continuations. It returns "" when
// no ExecStart= directive is found.
func extractExecStartLine(unitText string) string {
	lines := strings.Split(unitText, "\n")
	for i := 0; i < len(lines); i++ {
		trimmed := strings.TrimSpace(lines[i])
		if !strings.HasPrefix(trimmed, "ExecStart=") {
			continue
		}
		cmd := strings.TrimPrefix(trimmed, "ExecStart=")
		// Append following lines while the command ends with a continuation backslash.
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

// parseExecStart reconstructs DeployOpts from an ExecStart command line: the first
// field is the binary path and the rest are recognized flags. The presence of
// -domain implies builtin TLS; its absence implies proxy mode. When only a
// -public-issuer-url is present, the domain is recovered from that URL.
func parseExecStart(execStart string) DeployOpts {
	fields := normalizeFlagTokens(strings.Fields(execStart))
	var o DeployOpts
	sawDomain := false
	if len(fields) > 0 {
		o.BinPath = fields[0]
	}
	for i := 1; i < len(fields); i++ {
		// val consumes and returns the next token as the current flag's value.
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
			if o.Domain == "" {
				o.Domain = domainFromURL(val())
			} else {
				val() // consume the value even when an explicit domain wins
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

// normalizeFlagTokens splits "-flag=value" tokens into separate "-flag" and
// "value" tokens so the parser can treat both flag syntaxes uniformly. Non-flag
// tokens pass through unchanged.
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

// domainFromURL extracts the host portion of a URL by stripping the scheme and
// any path. The input need not be a full URL.
func domainFromURL(u string) string {
	u = strings.TrimPrefix(u, "https://")
	u = strings.TrimPrefix(u, "http://")
	if i := strings.IndexByte(u, '/'); i >= 0 {
		u = u[:i]
	}
	return u
}

// adoptFromUnit reads an installed unit file and recovers the DeployOpts from its
// ExecStart line. The bool is false if the file cannot be read or has no ExecStart.
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

// serviceController abstracts the service-manager operations used by the service
// subcommand, allowing the systemctl implementation to be substituted in tests.
type serviceController interface {
	// UnitExists reports whether the unit file is present on disk.
	UnitExists() bool

	// Install writes the unit file and reloads the manager so it is picked up.
	Install(unit string) error

	// EnableNow enables the unit to start at boot and starts it immediately.
	EnableNow() error

	Start() error
	Stop() error
	Restart() error

	// Status returns a parsed snapshot of the unit's current state.
	Status() (ServiceStatus, error)

	// Logs returns up to the last n log lines for the unit.
	Logs(lines int) ([]string, error)
}

// systemctlController drives the service via the systemctl and journalctl binaries.
type systemctlController struct {
	name     string // unit name passed to systemctl/journalctl
	unitPath string // on-disk path of the unit file
}

// newSystemctlController returns a controller bound to the package's unit name and path.
func newSystemctlController() *systemctlController {
	return &systemctlController{name: serviceName, unitPath: serviceUnitPath}
}

// UnitExists reports whether the unit file exists on disk.
func (c *systemctlController) UnitExists() bool {
	_, err := os.Stat(c.unitPath)
	return err == nil
}

// Install writes the unit file with 0644 permissions and runs daemon-reload so
// systemd picks up the new or changed unit.
func (c *systemctlController) Install(unit string) error {
	if err := os.WriteFile(c.unitPath, []byte(unit), 0o644); err != nil {
		return fmt.Errorf("write unit %s: %w", c.unitPath, err)
	}
	return c.run("daemon-reload")
}

// EnableNow enables the unit for boot and starts it in a single systemctl call.
func (c *systemctlController) EnableNow() error { return c.run("enable", "--now", c.name) }
func (c *systemctlController) Start() error     { return c.run("start", c.name) }
func (c *systemctlController) Stop() error      { return c.run("stop", c.name) }
func (c *systemctlController) Restart() error   { return c.run("restart", c.name) }

// run executes systemctl with the given arguments, wrapping any failure with the
// combined output for diagnostics.
func (c *systemctlController) run(args ...string) error {
	out, err := exec.Command("systemctl", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl %s: %w: %s",
			strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// Status queries the unit's properties via "systemctl show" and parses them.
func (c *systemctlController) Status() (ServiceStatus, error) {
	out, err := exec.Command("systemctl", "show", c.name,
		"--property="+strings.Join(systemctlShowProps, ",")).Output()
	if err != nil {
		return ServiceStatus{}, fmt.Errorf("systemctl show %s: %w", c.name, err)
	}
	return parseServiceStatus(string(out)), nil
}

// Logs returns up to the last n journal lines for the unit, defaulting to 100 when
// n is non-positive. It returns a nil slice when the journal is empty.
func (c *systemctlController) Logs(lines int) ([]string, error) {
	if lines <= 0 {
		lines = 100
	}
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

// Compile-time check that systemctlController satisfies serviceController.
var _ serviceController = (*systemctlController)(nil)

// canManageSystemd reports whether the current process has the privileges needed
// to manage units: either it is running as root, or passwordless sudo is available.
func canManageSystemd() bool {
	if os.Geteuid() == 0 {
		return true
	}
	return sudoNonInteractiveOK()
}

// sudoNonInteractiveOK reports whether sudo is installed and can run without
// prompting for a password ("sudo -n true" succeeds).
func sudoNonInteractiveOK() bool {
	if _, err := exec.LookPath("sudo"); err != nil {
		return false
	}
	return exec.Command("sudo", "-n", "true").Run() == nil
}

// runServiceSubcommand implements the "service" subcommand. It parses the verb
// and flags, builds DeployOpts, and dispatches to the systemctl controller,
// returning a process exit code (0 success, 1 runtime error, 2 usage error).
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
	// A domain is required to render URLs and (in builtin mode) request certificates.
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

// dispatchServiceVerb runs a single service verb against the controller, writing
// human-readable results to out and returning an error for failures or an
// unrecognized verb.
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

// formatServiceStatusLine renders a one-line human-readable summary of a status,
// e.g. "active (running) since <time> pid <n>".
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
