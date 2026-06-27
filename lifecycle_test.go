package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

// fakeHealth returns a canned health result and latency for any URL.
type fakeHealth struct {
	ok  bool
	lat time.Duration
}

func (f fakeHealth) Healthz(string) (bool, time.Duration) { return f.ok, f.lat }

// fakePort reports reachability from a fixed host:port set.
type fakePort struct{ open map[string]bool }

func (f fakePort) Reachable(hp string) bool { return f.open[hp] }

// fakeCert returns a canned certificate expiry and known flag.
type fakeCert struct {
	exp   time.Time
	known bool
}

func (f fakeCert) Expiry(string, string) (time.Time, bool) { return f.exp, f.known }

// healthURL is the public https /healthz for built-in TLS and the loopback http one for proxy mode,
// and empty when built-in mode has no domain.
func TestHealthURL(t *testing.T) {
	builtin := healthURL(DeployOpts{Mode: TLSModeBuiltin, Domain: "h.example"})
	if builtin != "https://h.example/healthz" {
		t.Errorf("builtin healthURL = %q", builtin)
	}
	proxy := healthURL(DeployOpts{Mode: TLSModeProxy}.withDefaults())
	if proxy != "http://127.0.0.1:8443/healthz" {
		t.Errorf("proxy healthURL = %q", proxy)
	}
	if got := healthURL(DeployOpts{Mode: TLSModeBuiltin}); got != "" {
		t.Errorf("builtin with no domain healthURL = %q, want empty", got)
	}
}

// Built-in mode probes :80/:443 and certificate expiry as part of the lifecycle snapshot.
func TestCollectLifecycleBuiltin(t *testing.T) {
	svc := &fakeController{status: ServiceStatus{Active: true, ActiveState: "active", SubState: "running"}}
	p := fakePort{open: map[string]bool{"127.0.0.1:80": true, "127.0.0.1:443": true}}
	cert := fakeCert{exp: time.Now().Add(60 * 24 * time.Hour), known: true}
	o := DeployOpts{Mode: TLSModeBuiltin, Domain: "issuer.x.example"}.withDefaults()

	snap := collectLifecycle(svc, fakeHealth{ok: true}, p, cert, o, "/tmp/acme")
	if !snap.Svc.Running() || !snap.Health || !snap.CheckPorts ||
		!snap.Port80 || !snap.Port443 || !snap.CertKnown {
		t.Errorf("unexpected snapshot: %+v", snap)
	}
	if snap.HealthURL != "https://issuer.x.example/healthz" {
		t.Errorf("HealthURL = %q", snap.HealthURL)
	}
}

// Proxy mode skips port probing since the proxy, not this service, owns :80/:443.
func TestCollectLifecycleProxy(t *testing.T) {
	svc := &fakeController{status: ServiceStatus{Active: true, ActiveState: "active", SubState: "running"}}
	o := DeployOpts{Mode: TLSModeProxy, Domain: "issuer.x.example"}.withDefaults()

	snap := collectLifecycle(svc, fakeHealth{ok: true}, fakePort{}, fakeCert{}, o, "")
	if snap.CheckPorts {
		t.Error("proxy mode must not probe :80/:443 (it doesn't own them)")
	}
	if snap.HealthURL != "http://127.0.0.1:8443/healthz" {
		t.Errorf("HealthURL = %q", snap.HealthURL)
	}
}

// formatLifecycle renders a snapshot into the status report across running, failed, not-installed,
// proxy, and cert-issuing cases.
func TestFormatLifecycle(t *testing.T) {
	now := time.Date(2026, 6, 21, 12, 0, 0, 0, time.UTC)

	t.Run("running builtin with cert", func(t *testing.T) {
		snap := LifecycleSnapshot{
			Mode: TLSModeBuiltin, Configured: true,
			Svc: ServiceStatus{Active: true, ActiveState: "active", SubState: "running",
				Since: now.Add(-2 * time.Hour)},
			Health: true, HealthURL: "https://h/healthz", PublicURL: "https://h",
			CertKnown: true, CertExpiry: now.Add(60 * 24 * time.Hour),
			CheckPorts: true, Port80: true, Port443: true, Version: "v1.2.3",
		}
		got := formatLifecycle(snap, now)
		for _, want := range []string{
			"active (running)", "uptime 2h0m", "Health     ok", "built-in Let's Encrypt",
			"expires 2026-08-20", ":80 ✓", ":443 ✓", "v1.2.3",
		} {
			if !strings.Contains(got, want) {
				t.Errorf("missing %q in:\n%s", want, got)
			}
		}
	})

	t.Run("failed", func(t *testing.T) {
		snap := LifecycleSnapshot{Svc: ServiceStatus{ActiveState: "failed", SubState: "failed"}}
		if !strings.Contains(formatLifecycle(snap, now), "✕ failed") {
			t.Error("want failed marker")
		}
	})

	t.Run("not installed", func(t *testing.T) {
		if !strings.Contains(formatLifecycle(LifecycleSnapshot{}, now), "not installed") {
			t.Error("want not-installed marker")
		}
	})

	t.Run("proxy hides ports + cert", func(t *testing.T) {
		snap := LifecycleSnapshot{Mode: TLSModeProxy, PublicURL: "https://h", Health: true}
		got := formatLifecycle(snap, now)
		if !strings.Contains(got, "reverse proxy") {
			t.Errorf("want reverse-proxy cert note:\n%s", got)
		}
		if strings.Contains(got, ":80") {
			t.Error("proxy mode must not render ports")
		}
	})

	t.Run("builtin cert issuing", func(t *testing.T) {
		snap := LifecycleSnapshot{Mode: TLSModeBuiltin, CertKnown: false}
		if !strings.Contains(formatLifecycle(snap, now), "issuing") {
			t.Error("want issuing marker during ACME window")
		}
	})
}

// humanizeDuration renders durations compactly and clamps negatives to "0m".
func TestHumanizeDuration(t *testing.T) {
	cases := map[time.Duration]string{
		9 * time.Minute:              "9m",
		2*time.Hour + 14*time.Minute: "2h14m",
		50 * time.Hour:               "2d2h",
		-5 * time.Minute:             "0m",
	}
	for d, want := range cases {
		if got := humanizeDuration(d); got != want {
			t.Errorf("humanizeDuration(%v) = %q, want %q", d, got, want)
		}
	}
}

// leafNotAfter extracts the NotAfter of the leaf certificate from PEM, failing on non-PEM input.
func TestLeafNotAfter(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	notAfter := time.Date(2027, 9, 19, 0, 0, 0, 0, time.UTC)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    notAfter.Add(-90 * 24 * time.Hour),
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	got, ok := leafNotAfter(pemBytes)
	if !ok || !got.Equal(notAfter) {
		t.Errorf("leafNotAfter = %v ok=%v, want %v", got, ok, notAfter)
	}
	if _, ok := leafNotAfter([]byte("not a pem")); ok {
		t.Error("expected ok=false on non-PEM input")
	}
}
