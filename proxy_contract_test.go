package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"testing"
)

// A local reverse proxy must preserve the public host, method, body, and client
// chain while Creator Server trusts forwarded addresses only from loopback.
func TestLoopbackReverseProxyContract(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if r.Method != http.MethodPost || string(body) != `{"probe":true}` {
			t.Fatalf("origin request = %s %q", r.Method, body)
		}
		if r.Host != "issuer.example.com" {
			t.Fatalf("origin Host = %q", r.Host)
		}
		if got := clientIP(r, loopbackCIDRs()); got != "198.51.100.24" {
			t.Fatalf("clientIP through loopback proxy = %q", got)
		}
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer origin.Close()

	target, err := url.Parse(origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	proxy := httptest.NewServer(httputil.NewSingleHostReverseProxy(target))
	defer proxy.Close()

	req, err := http.NewRequest(http.MethodPost, proxy.URL+"/v1/redeem", strings.NewReader(`{"probe":true}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "issuer.example.com"
	req.Header.Set("X-Forwarded-For", "198.51.100.24")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent || resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("proxy response = %d cache=%q", resp.StatusCode, resp.Header.Get("Cache-Control"))
	}
}

func TestDirectPeerCannotSpoofForwardedClient(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	req.RemoteAddr = "203.0.113.9:4321"
	req.Header.Set("X-Forwarded-For", "198.51.100.24")
	if got := clientIP(req, loopbackCIDRs()); got != "203.0.113.9" {
		t.Fatalf("direct spoof resolved to %q", got)
	}
}
