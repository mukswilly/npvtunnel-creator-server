package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// lifecycle.go is the read model behind the console's Server screen: it probes
// the running deployment (systemd state, /healthz, listening ports, TLS cert)
// and formats a snapshot. The probes are injectable interfaces so the screen
// renders against fakes in tests — no live server, no root, no network.

// ─── injectable probes ─────────────────────────────────────────────────

type healthChecker interface {
	// Healthz GETs url and reports whether it answered 200, plus how long it
	// took (shown as a latency hint).
	Healthz(url string) (ok bool, latency time.Duration)
}

type portChecker interface {
	// Reachable reports whether a TCP connect to hostport succeeds (i.e. the
	// port is bound and accepting).
	Reachable(hostport string) bool
}

type certInspector interface {
	// Expiry returns the leaf cert's NotAfter from an autocert DirCache.
	// known=false during the ACME issuance window (no cert cached yet).
	Expiry(acmeCacheDir, domain string) (expiry time.Time, known bool)
}

// httpHealthChecker is the real healthChecker.
type httpHealthChecker struct{ timeout time.Duration }

func (h httpHealthChecker) Healthz(url string) (bool, time.Duration) {
	to := h.timeout
	if to <= 0 {
		to = 3 * time.Second
	}
	client := &http.Client{Timeout: to}
	start := time.Now()
	resp, err := client.Get(url)
	lat := time.Since(start)
	if err != nil {
		return false, lat
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK, lat
}

// dialPortChecker is the real portChecker.
type dialPortChecker struct{ timeout time.Duration }

func (d dialPortChecker) Reachable(hostport string) bool {
	to := d.timeout
	if to <= 0 {
		to = 2 * time.Second
	}
	conn, err := net.DialTimeout("tcp", hostport, to)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// autocertInspector reads the leaf cert from the binary's autocert DirCache
// (<state-dir>/acme). The cache file is named exactly the domain and holds the
// PEM bundle (key + chain, leaf first).
type autocertInspector struct{}

func (autocertInspector) Expiry(acmeCacheDir, domain string) (time.Time, bool) {
	if acmeCacheDir == "" || domain == "" {
		return time.Time{}, false
	}
	data, err := os.ReadFile(filepath.Join(acmeCacheDir, domain))
	if err != nil {
		return time.Time{}, false
	}
	return leafNotAfter(data)
}

// leafNotAfter parses the first CERTIFICATE block in a PEM bundle and returns
// its NotAfter. Pure (no I/O) so it's unit-testable with a fixture cert.
func leafNotAfter(pemBytes []byte) (time.Time, bool) {
	for {
		var block *pem.Block
		block, pemBytes = pem.Decode(pemBytes)
		if block == nil {
			return time.Time{}, false
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return time.Time{}, false
		}
		return cert.NotAfter, true
	}
}

// ─── snapshot + collection ─────────────────────────────────────────────

// LifecycleSnapshot is the fully-resolved state the Server screen renders.
type LifecycleSnapshot struct {
	Mode          TLSMode
	Configured    bool // a deployment is known (domain set)
	Svc           ServiceStatus
	SvcErr        error
	Health        bool
	HealthURL     string
	HealthLatency time.Duration
	PublicURL     string
	CertExpiry    time.Time
	CertKnown     bool
	CheckPorts    bool // ports are only meaningful in built-in TLS mode
	Port80        bool
	Port443       bool
	Version       string
}

// collectLifecycle runs every probe and assembles a snapshot. Built-in TLS is
// the only mode where this box owns :80/:443 and the cert, so port + cert
// probes are gated on it; proxy mode's external HTTPS is unverifiable from here.
func collectLifecycle(svc serviceController, h healthChecker, p portChecker, c certInspector, o DeployOpts, acmeCacheDir string) LifecycleSnapshot {
	snap := LifecycleSnapshot{
		Mode:       o.Mode,
		Configured: o.Domain != "",
		PublicURL:  o.PublicURL(),
		Version:    version,
	}
	snap.Svc, snap.SvcErr = svc.Status()

	snap.HealthURL = healthURL(o)
	if snap.HealthURL != "" {
		snap.Health, snap.HealthLatency = h.Healthz(snap.HealthURL)
	}

	// Port/cert probes only make sense once a built-in-TLS deployment exists
	// (a domain is set). Skipping them when unconfigured avoids pointless
	// localhost dials on the not-yet-set-up screen.
	if o.Mode == TLSModeBuiltin && o.Domain != "" {
		snap.CheckPorts = true
		snap.Port80 = p.Reachable("127.0.0.1:80")
		snap.Port443 = p.Reachable("127.0.0.1:443")
		snap.CertExpiry, snap.CertKnown = c.Expiry(acmeCacheDir, o.Domain)
	}
	return snap
}

// healthURL is where /healthz is reachable for this deployment: the loopback
// HTTP listener in proxy mode, the public HTTPS origin in built-in mode.
func healthURL(o DeployOpts) string {
	switch o.Mode {
	case TLSModeProxy:
		addr := o.Addr
		if addr == "" {
			addr = defaultProxyAddr
		}
		return "http://" + addr + "/healthz"
	default:
		if o.Domain == "" {
			return ""
		}
		return o.PublicURL() + "/healthz"
	}
}

// ─── pure formatting ───────────────────────────────────────────────────

// formatLifecycle renders the Server-screen status block. Pure (snapshot in,
// string out) so it's table-tested directly; the screen wraps it in a
// TextView. No color tags here — the screen adds those around the block.
func formatLifecycle(snap LifecycleSnapshot, now time.Time) string {
	var b strings.Builder

	service := "○ not installed"
	switch {
	case snap.SvcErr != nil:
		service = "? unknown"
	case snap.Svc.Running():
		service = "● active (running)"
		if !snap.Svc.Since.IsZero() {
			service += "   uptime " + humanizeDuration(now.Sub(snap.Svc.Since))
		}
	case snap.Svc.Failed():
		service = "✕ failed"
	case snap.Svc.ActiveState != "":
		service = "○ " + snap.Svc.ActiveState
		if snap.Svc.SubState != "" {
			service += " (" + snap.Svc.SubState + ")"
		}
	}
	fmt.Fprintf(&b, "  Service    %s\n", service)

	health := "unreachable"
	if snap.Health {
		health = "ok"
	}
	if snap.HealthURL != "" {
		fmt.Fprintf(&b, "  Health     %s   %s\n", health, snap.HealthURL)
	} else {
		fmt.Fprintf(&b, "  Health     %s\n", health)
	}

	if snap.PublicURL != "" {
		fmt.Fprintf(&b, "  Address    %s   %s\n", snap.PublicURL, tlsModeLabel(snap.Mode))
	} else {
		b.WriteString("  Address    (not configured)\n")
	}

	switch {
	case snap.Mode != TLSModeBuiltin:
		b.WriteString("  TLS cert   reverse proxy — verify off-box\n")
	case snap.CertKnown:
		days := int(snap.CertExpiry.Sub(now).Hours() / 24)
		fmt.Fprintf(&b, "  TLS cert   valid · expires %s (%dd)\n",
			snap.CertExpiry.UTC().Format("2006-01-02"), days)
	default:
		b.WriteString("  TLS cert   issuing… (no cert cached yet)\n")
	}

	if snap.CheckPorts {
		fmt.Fprintf(&b, "  Ports      :80 %s   :443 %s\n", checkMark(snap.Port80), checkMark(snap.Port443))
	}

	fmt.Fprintf(&b, "  Version    %s\n", snap.Version)
	return b.String()
}

func tlsModeLabel(m TLSMode) string {
	if m == TLSModeProxy {
		return "reverse proxy"
	}
	return "built-in Let's Encrypt"
}

func checkMark(ok bool) string {
	if ok {
		return "✓"
	}
	return "✗"
}

// humanizeDuration renders an uptime as "2d3h" / "2h14m" / "9m" (minute
// resolution — uptimes don't need seconds).
func humanizeDuration(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	d = d.Round(time.Minute)
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	switch {
	case h >= 24:
		return fmt.Sprintf("%dd%dh", h/24, h%24)
	case h > 0:
		return fmt.Sprintf("%dh%dm", h, m)
	default:
		return fmt.Sprintf("%dm", m)
	}
}
