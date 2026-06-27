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

// healthChecker, portChecker, and certInspector abstract the external probes a
// status check makes, so the status rendering can be tested with fakes.
type healthChecker interface {
	Healthz(url string) (ok bool, latency time.Duration)
}

type portChecker interface {
	Reachable(hostport string) bool
}

type certInspector interface {
	Expiry(acmeCacheDir, domain string) (expiry time.Time, known bool)
}

// httpHealthChecker probes a /healthz URL over HTTP.
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

// dialPortChecker reports whether a TCP port accepts connections.
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

// autocertInspector reads the cached Let's Encrypt certificate to find its
// expiry. autocert stores the leaf under <cacheDir>/<domain>.
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

// leafNotAfter returns the NotAfter of the first certificate in a PEM bundle.
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

// LifecycleSnapshot is a point-in-time view of the deployment: service state,
// reachability, TLS posture, and version, used by the status command and the
// console's Server screen.
type LifecycleSnapshot struct {
	Mode          TLSMode
	Configured    bool
	Svc           ServiceStatus
	SvcErr        error
	Health        bool
	HealthURL     string
	HealthLatency time.Duration
	PublicURL     string
	CertExpiry    time.Time
	CertKnown     bool
	CheckPorts    bool
	Port80        bool
	Port443       bool
	Version       string
}

// collectLifecycle assembles a snapshot from the service controller and the
// probes. Port and certificate checks run only for built-in TLS deployments.
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

	if o.Mode == TLSModeBuiltin && o.Domain != "" {
		snap.CheckPorts = true
		snap.Port80 = p.Reachable("127.0.0.1:80")
		snap.Port443 = p.Reachable("127.0.0.1:443")
		snap.CertExpiry, snap.CertKnown = c.Expiry(acmeCacheDir, o.Domain)
	}
	return snap
}

// healthURL returns the /healthz URL to probe for the given deployment: the
// local proxy address in reverse-proxy mode, otherwise the public URL.
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

// formatLifecycle renders a snapshot as an aligned, human-readable status block.
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

// humanizeDuration formats a duration as a compact d/h/m string.
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
