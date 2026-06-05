// creator-server: HTTPS reference implementation of the NpvTunnel
// Phase-3 issuance + share-link redemption protocol.
//
// Run with -addr / -cert / -key flags; see README.md for ops notes.
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
	"strings"
	"syscall"
	"time"
)

// parseTrustedProxies parses a comma-separated list of CIDRs into
// []*net.IPNet. A bare IP (no "/prefix") is accepted as a single-host
// CIDR. Returns an error naming the offending entry so an operator typo
// fails loudly at startup rather than silently disabling proxy trust.
func parseTrustedProxies(csv string) ([]*net.IPNet, error) {
	var out []*net.IPNet
	for _, raw := range strings.Split(csv, ",") {
		entry := strings.TrimSpace(raw)
		if entry == "" {
			continue
		}
		if !strings.Contains(entry, "/") {
			// Bare IP → /32 (v4) or /128 (v6).
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

func main() {
	// Subcommand dispatch. The default (no subcommand) preserves the
	// existing flag-based server entrypoint, so existing systemd units
	// + ops scripts keep working unchanged.
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "mint":
			os.Exit(runMintSubcommand(os.Args[2:]))
		case "mint-share-link":
			os.Exit(runMintShareLinkSubcommand(os.Args[2:]))
		case "revoke-token":
			os.Exit(runRevokeTokenSubcommand(os.Args[2:]))
		case "version", "-v", "--version":
			os.Exit(runVersionSubcommand())
		case "help", "-h", "--help":
			// Fall through to flag-parsing below, which prints usage
			// when -h is encountered.
		default:
			// If it doesn't look like a flag (no leading dash) we
			// treat it as an unknown subcommand. Anything starting
			// with - keeps falling through to the legacy flag parser.
			if !strings.HasPrefix(os.Args[1], "-") {
				fmt.Fprintf(os.Stderr,
					"creator-server: unknown subcommand %q\n"+
						"  subcommands: mint, mint-share-link, revoke-token, version\n"+
						"  no subcommand: run the issuer server (see -h for flags)\n",
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
	}
	srv := NewServer(state, logger)

	httpSrv := &http.Server{
		Addr:              *addr,
		Handler:           srv.Router(),
		ReadHeaderTimeout: 10 * time.Second,
		// ReadTimeout / WriteTimeout bound a single slow client. Request
		// bodies are already size-capped (io.LimitReader in the
		// handlers); these cap the TIME a client may take to trickle one
		// in or read a response, closing the slow-body resource-
		// exhaustion vector that ReadHeaderTimeout alone doesn't. 30s is
		// generous for a mobile client on a degraded censored-region
		// link while still bounding a deliberate slowloris.
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// Graceful shutdown on SIGINT / SIGTERM.
	shutdownCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Periodically evict inactive rate-limiter entries. Without this the
	// per-devicePk and per-IP maps grow for the life of the process (an
	// attacker minting fresh keypairs or rotating source IPs can drive
	// unbounded growth). The sweep window matches the 1h limiter window.
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

	go func() {
		var err error
		if *certFile != "" {
			if *keyFile == "" {
				logger.Error("-cert provided without -key")
				os.Exit(2)
			}
			logger.Info("listening (TLS)", "addr", *addr)
			err = httpSrv.ListenAndServeTLS(*certFile, *keyFile)
		} else {
			logger.Warn("listening (HTTP — development only, DO NOT expose to the public internet)", "addr", *addr)
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
	if err := httpSrv.Shutdown(shutdownDeadline); err != nil {
		logger.Error("graceful shutdown failed", "err", err)
		os.Exit(1)
	}
	state.Close()
	logger.Info("bye")
}
