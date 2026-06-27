// Command creator-server is a config-distribution server: it signs and hands
// out VPN configuration payloads over an HTTP API and via redeemable
// share-link tokens.
//
// Run with no subcommand to start the issuer server (POST /v1/issue, POST
// /v1/redeem). On a terminal with no arguments it instead opens the interactive
// console. The subcommands cover setup, config/token management, status,
// backup, and one-off minting; run with -h for server flags or "help" for the
// subcommand list.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

const letsEncryptStagingURL = "https://acme-staging-v02.api.letsencrypt.org/directory"

// parseTrustedProxies parses a comma-separated list of IPs/CIDRs into networks.
// Bare IPs are promoted to /32 (IPv4) or /128 (IPv6) host routes.
func parseTrustedProxies(csv string) ([]*net.IPNet, error) {
	var out []*net.IPNet
	for _, raw := range strings.Split(csv, ",") {
		entry := strings.TrimSpace(raw)
		if entry == "" {
			continue
		}
		if !strings.Contains(entry, "/") {

			if ip := net.ParseIP(entry); ip != nil {
				if ip.To4() != nil {
					entry += "/32"
				} else {
					entry += "/128"
				}
			}
		}
		_, ipNet, err := net.ParseCIDR(entry)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR %q: %w", raw, err)
		}
		out = append(out, ipNet)
	}
	return out, nil
}

// flagWasSet reports whether the named flag was explicitly passed (as opposed
// to left at its default).
func flagWasSet(name string) bool {
	set := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == name {
			set = true
		}
	})
	return set
}

// isLoopbackBind reports whether addr binds to localhost.
func isLoopbackBind(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	if host == "" {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func loopbackCIDRs() []*net.IPNet {
	nets, _ := parseTrustedProxies("127.0.0.1/32,::1/128")
	return nets
}

// csvHasDefaultRoute reports whether the list contains a default route, which
// would let any peer be treated as a trusted proxy.
func csvHasDefaultRoute(csv string) bool {
	for _, raw := range strings.Split(csv, ",") {
		switch strings.TrimSpace(raw) {
		case "0.0.0.0/0", "::/0":
			return true
		}
	}
	return false
}

func main() {

	// Bare invocation on a terminal launches the interactive console.
	if len(os.Args) == 1 && stdinIsTTY() {
		os.Exit(runMenuSubcommand(nil))
	}

	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "menu", "console", "tui":
			os.Exit(runMenuSubcommand(os.Args[2:]))
		case "mint":
			os.Exit(runMintSubcommand(os.Args[2:]))
		case "mint-share-link":
			os.Exit(runMintShareLinkSubcommand(os.Args[2:]))
		case "revoke-token":
			os.Exit(runRevokeTokenSubcommand(os.Args[2:]))
		case "init":
			os.Exit(runInitSubcommand(os.Args[2:]))
		case "config":
			os.Exit(runConfigSubcommand(os.Args[2:]))
		case "token":
			os.Exit(runTokenSubcommand(os.Args[2:]))
		case "status":
			os.Exit(runStatusSubcommand(os.Args[2:]))
		case "backup":
			os.Exit(runBackupSubcommand(os.Args[2:]))
		case "service":
			os.Exit(runServiceSubcommand(os.Args[2:]))
		case "version", "-v", "--version":
			os.Exit(runVersionSubcommand())
		case "help", "-h", "--help":
			// Fall through to flag.Parse so -h prints the server usage.
		default:
			// A non-flag first argument is an unknown subcommand; anything
			// starting with "-" is treated as a server flag.
			if !strings.HasPrefix(os.Args[1], "-") {
				fmt.Fprintf(os.Stderr,
					"creator-server: unknown subcommand %q\n"+
						"  console:        menu  (interactive; also: bare `creator-server` on a terminal)\n"+
						"  setup & manage: init, service, config, token, status, backup\n"+
						"  share/handout:  mint-share-link, revoke-token, mint\n"+
						"  other:          version\n"+
						"  no subcommand:  run the issuer server (see -h for flags)\n",
					os.Args[1])
				os.Exit(2)
			}
		}
	}

	addr := flag.String("addr", ":8443", "bind address")
	certFile := flag.String("cert", "", "TLS cert PEM (if empty, runs HTTP)")
	keyFile := flag.String("key", "", "TLS key PEM (required if -cert set)")
	stateDir := flag.String("state-dir", "",
		"directory for persistent state (creator-key.pem, configs.json). "+
			"Empty = ephemeral in-memory keys (dev/test only — every restart "+
			"breaks recipients).")
	publicIssuerURL := flag.String("public-issuer-url", "",
		"externally-reachable URL of this server's /v1/issue endpoint "+
			"(e.g. https://issuer.alpha.example/v1/issue). Required for "+
			"/v1/redeem to mint envelopes that point recipients back at "+
			"the right place. Empty disables /v1/redeem with a 500.")
	trustedProxies := flag.String("trusted-proxy", "",
		"comma-separated CIDRs of trusted reverse proxies (e.g. "+
			"127.0.0.1/32,10.0.0.0/8). X-Forwarded-For is honored ONLY "+
			"from peers in these ranges. Empty (default) ignores "+
			"X-Forwarded-For entirely — correct when this server faces "+
			"the internet directly, so clients can't spoof their "+
			"rate-limit key.")
	domain := flag.String("domain", "",
		"public hostname for automatic HTTPS via Let's Encrypt (e.g. "+
			"issuer.yourdomain.example). When set, this binary obtains and "+
			"auto-renews its own TLS certificate — no reverse proxy needed — "+
			"serves HTTPS on :443, answers ACME HTTP-01 challenges on :80, and "+
			"derives -public-issuer-url automatically. Requires ports 80+443 "+
			"reachable and the domain's DNS pointing here.")
	acmeEmail := flag.String("acme-email", "",
		"contact email for the Let's Encrypt account (recommended with "+
			"-domain; used for certificate-expiry notices).")
	acmeCacheDir := flag.String("acme-cache-dir", "",
		"directory to cache Let's Encrypt certificates + account key in. "+
			"Defaults to <state-dir>/acme, or ./acme-cache when -state-dir is empty.")
	acmeStaging := flag.Bool("acme-staging", false,
		"use the Let's Encrypt STAGING environment (untrusted certs, relaxed "+
			"rate limits) to test the ACME flow without burning production quota.")
	debug := flag.Bool("debug", false, "verbose logging")
	flag.Parse()

	level := slog.LevelInfo
	if *debug {
		level = slog.LevelDebug
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
	slog.SetDefault(logger)

	state, err := NewStateWithDir(*stateDir)
	if err != nil {
		logger.Error("init state", "err", err)
		os.Exit(1)
	}

	if *domain != "" && strings.ContainsAny(*domain, "/: ") {
		logger.Error("-domain must be a bare hostname (no scheme, port, or path)", "got", *domain)
		os.Exit(2)
	}
	effectiveAddr := *addr
	if *domain != "" && !flagWasSet("addr") {
		// With -domain, default the bind to the HTTPS port.
		effectiveAddr = ":443"
	}
	if *publicIssuerURL == "" && *domain != "" {
		*publicIssuerURL = "https://" + *domain + "/v1/issue"
		logger.Info("derived -public-issuer-url from -domain", "url", *publicIssuerURL)
	}

	if *publicIssuerURL != "" {
		if !strings.HasPrefix(*publicIssuerURL, "https://") {
			logger.Error("public-issuer-url must start with https://", "got", *publicIssuerURL)
			os.Exit(2)
		}
		state.PublicIssuerURL = *publicIssuerURL
	} else {
		logger.Warn("no -public-issuer-url set; /v1/redeem will return 500")
	}
	if *trustedProxies != "" {
		nets, perr := parseTrustedProxies(*trustedProxies)
		if perr != nil {
			logger.Error("parse -trusted-proxy", "err", perr)
			os.Exit(2)
		}
		state.TrustedProxies = nets
		logger.Info("trusting X-Forwarded-For from proxies", "cidrs", *trustedProxies)
		if csvHasDefaultRoute(*trustedProxies) {
			logger.Warn("-trusted-proxy includes a default route (0.0.0.0/0 or ::/0): " +
				"ANY client could then spoof X-Forwarded-For to dodge the per-IP " +
				"rate limit. List only your actual proxy's address.")
		}
	} else if *domain == "" && isLoopbackBind(effectiveAddr) {
		// Bound to localhost without an explicit proxy list: a local reverse
		// proxy is the only possible peer, so trust its forwarded addresses.
		state.TrustedProxies = loopbackCIDRs()
		logger.Info("bound to loopback; trusting X-Forwarded-For from localhost proxies",
			"cidrs", "127.0.0.1/32,::1/128")
	}
	if *stateDir == "" {
		logger.Warn("running with ephemeral creator key — production should set -state-dir")
	} else {
		logger.Info("state loaded",
			"stateDir", *stateDir,
			"creatorPubkey", state.CreatorPubKeyCompressedB64(),
			"hasConfigRegistry", state.HasConfigRegistry(),
			"publicIssuerURL", *publicIssuerURL,
		)
		if state.KeyWasCreated() {
			logger.Warn("FIRST RUN: a new creator signing key was generated. "+
				"BACK IT UP NOW and store the copy off this machine — losing it "+
				"permanently breaks every recipient (they pin its public half).",
				"keyFile", filepath.Join(*stateDir, "creator-key.pem"),
				"creatorPubkey", state.CreatorPubKeyCompressedB64(),
				"backupCmd", "creator-server backup -state-dir "+*stateDir,
			)
		}
	}
	srv := NewServer(state, logger)

	httpSrv := &http.Server{
		Addr:              effectiveAddr,
		Handler:           srv.Router(),
		ReadHeaderTimeout: 10 * time.Second,

		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	shutdownCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Periodically evict idle rate-limiter buckets so memory stays bounded.
	sweepTicker := time.NewTicker(10 * time.Minute)
	defer sweepTicker.Stop()
	go func() {
		for {
			select {
			case <-shutdownCtx.Done():
				return
			case <-sweepTicker.C:
				state.SweepRateLimiters(1 * time.Hour)
			}
		}
	}()

	// With -domain, run an autocert manager: HTTPS on the main listener and an
	// HTTP-01 challenge responder on :80 for issuance and renewal.
	var challengeSrv *http.Server
	if *domain != "" {
		cacheDir := *acmeCacheDir
		if cacheDir == "" {
			if *stateDir != "" {
				cacheDir = filepath.Join(*stateDir, "acme")
			} else {
				cacheDir = "acme-cache"
			}
		}
		if mkErr := os.MkdirAll(cacheDir, 0o700); mkErr != nil {
			logger.Error("create acme cache dir", "dir", cacheDir, "err", mkErr)
			os.Exit(1)
		}
		m := &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(*domain),
			Cache:      autocert.DirCache(cacheDir),
			Email:      *acmeEmail,
		}
		if *acmeStaging {
			m.Client = &acme.Client{DirectoryURL: letsEncryptStagingURL}
		}
		httpSrv.TLSConfig = m.TLSConfig()

		challengeSrv = &http.Server{
			Addr:              ":80",
			Handler:           m.HTTPHandler(nil),
			ReadHeaderTimeout: 10 * time.Second,
		}
		go func() {
			if cerr := challengeSrv.ListenAndServe(); cerr != nil && !errors.Is(cerr, http.ErrServerClosed) {
				logger.Error("ACME challenge listener (:80) failed — Let's Encrypt cannot issue or renew without it", "err", cerr)
			}
		}()
	}

	// Pick the listener mode: built-in HTTPS (-domain), supplied cert/key
	// (-cert/-key), or plain HTTP (development only).
	go func() {
		var err error
		switch {
		case *domain != "":
			logger.Info("listening (built-in HTTPS via Let's Encrypt)",
				"addr", httpSrv.Addr, "domain", *domain, "acmeStaging", *acmeStaging)
			err = httpSrv.ListenAndServeTLS("", "")
		case *certFile != "":
			if *keyFile == "" {
				logger.Error("-cert provided without -key")
				os.Exit(2)
			}
			logger.Info("listening (TLS)", "addr", httpSrv.Addr)
			err = httpSrv.ListenAndServeTLS(*certFile, *keyFile)
		default:
			logger.Warn("listening (HTTP — development only, DO NOT expose to the public internet)", "addr", httpSrv.Addr)
			err = httpSrv.ListenAndServe()
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("server exited unexpectedly", "err", err)
			os.Exit(1)
		}
	}()

	<-shutdownCtx.Done()
	logger.Info("shutting down…")

	shutdownDeadline, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if challengeSrv != nil {
		_ = challengeSrv.Shutdown(shutdownDeadline)
	}
	if err := httpSrv.Shutdown(shutdownDeadline); err != nil {
		logger.Error("graceful shutdown failed", "err", err)
		os.Exit(1)
	}
	state.Close()
	logger.Info("bye")
}
