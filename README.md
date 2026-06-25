# creator-server

**A small config-distribution server for NpvTunnel's share-link method.**

NpvTunnel users connect to VPN servers — v2ray and SSH — that
creators run themselves. **This is not one of those.** This is a little
optional helper that does just one thing: it's one of the ways a creator hands
a config to their users — the **share-link** way.

You run it (on a cheap VPS) only if you want users to get your config by
**tapping a link** instead of you sending them a config file. When someone taps
your link, this server gives their app the config — so the config never sits
inside the file or link you posted publicly. Each handout is gated (attestation
and rate limits, both optional) and carries a signed receipt the app verifies.

> **Don't want to run anything?** You don't have to. NpvTunnel also exports
> configs as plain files — including passphrase-protected ones — with no server
> at all. This repo is only for creators who specifically want the share-link
> distribution method.

The server holds no VPN technique of its own — the config you serve is whatever
*you* put in its config file, pointing at *your* VPN servers. It's open source
so anyone can verify exactly what it does.

---

## Who this is for

- **Creators** who want to distribute a config by share link, control who can
  use it (redemption limits + burnable links), and keep a leaked config
  short-lived. **Most of this README is for you.** You need a VPS and a domain,
  not Go experience.
- **Auditors / the curious** — see [Trust & verification](#trust--verification).
- **Contributors** — see [Build & contribute](#build--contribute).

## How it fits together

You already run your own VPN server(s). Nothing here replaces them. This server
sits beside them and only handles *distributing the config that points at them*:

```
   Your VPN servers (v2ray / SSH)  ◀── users' apps connect here for the tunnel
            ▲
            │ your config points at them
            │
   ┌────────┴─────────┐     you post a LINK (no config inside):
   │  this server     │ ───  npvtunnel://join?…  ───▶  user taps it
   │ (config handout) │
   └────────┬─────────┘
            │  each time the user's app connects, it asks this server for the
            └─ config, which you authored in configs.json and which already
               works against your VPN server.
```

So:

- **The link/file you post contains no config** — just a pointer to this server.
- **The real config is fetched from this server**, gated by your attestation /
  rate-limit policy, with a signed receipt the app verifies before using it.
- **This server does not run or control your VPN server.** It distributes a
  static, already-working config you placed in `configs.json` for a data
  plane run by you (or whoever runs it). The `expiresAt` it returns is a
  client *re-fetch cadence*, not a server-enforced expiry.

---

## Quick start

Install a signed release binary — no Go toolchain needed:

```sh
curl -fsSL https://raw.githubusercontent.com/mukswilly/npvtunnel-creator-server/main/install.sh | sh
```

The installer downloads the right binary for your CPU, **verifies its checksum
and cosign signature**, installs it to `/usr/local/bin/creator-server`, and (as
root) creates the `creator` user, a state directory, and a systemd unit. Read it
first if you like: `curl -fsSL …/install.sh | less`.

**Docker:**

```sh
docker run -d --name creator-server --restart unless-stopped \
  -v creator-state:/var/lib/creator-server -p 127.0.0.1:8443:8443 \
  ghcr.io/mukswilly/npvtunnel-creator-server:latest \
  -addr :8443 -state-dir /var/lib/creator-server \
  -public-issuer-url https://issuer.yourdomain.example/v1/issue
```

**From source** (Go 1.25+): `go build -o creator-server .` · check with
`creator-server version`.

---

## Deploy

> **Easiest path: let the console set it up.** After installing the binary, run
> `sudo -u creator creator-server`. The first-run **setup wizard** asks for your
> hostname + TLS mode, writes and starts the systemd unit, waits for HTTPS, and
> prompts you to back up your key — no flags, no editing units. The manual steps
> below are the scripted equivalents.

Shape: this binary on `127.0.0.1:8443` (proxy mode) or `:443` (built-in TLS), a
backed-up state directory.

1. **Provision** a small VPS (~$5/mo, `amd64` or `arm64`) and point a domain at
   it (e.g. `issuer.yourdomain.example`). This is separate from your VPN
   server(s).
2. **Install** with the one-liner above.
3. **Pick how TLS is terminated** — two options:

   **A. Built-in (simplest — no reverse proxy).** Let the binary obtain and
   auto-renew its own Let's Encrypt certificate. Install with
   `--builtin-tls issuer.yourdomain.example --acme-email you@example.com`, or
   run the binary directly:
   ```sh
   creator-server -state-dir /var/lib/creator-server \
     -domain issuer.yourdomain.example -acme-email you@example.com
   ```
   It serves `:443`, answers ACME challenges on `:80`, and derives
   `-public-issuer-url` for you. Needs ports 80+443 reachable and the
   domain's DNS pointing here.

   **B. Behind a reverse proxy.** Write the unit for proxy mode (one command —
   no editing files), then front `127.0.0.1:8443` with Caddy/nginx:
   ```sh
   sudo creator-server service install -tls proxy -domain issuer.yourdomain.example
   ```
   ```
   issuer.yourdomain.example { reverse_proxy 127.0.0.1:8443 }
   ```
   When bound to loopback the server auto-trusts `X-Forwarded-For` from
   localhost, so the standard local-proxy setup needs no `-trusted-proxy`.
5. **Start it:**
   ```sh
   sudo systemctl enable --now creator-server
   curl -sS http://127.0.0.1:8443/healthz   # → ok
   ```
6. **⚠ Back up your key.** First run generates `creator-key.pem` in the state
   dir. **Losing it breaks every recipient** (they pin its public half).
   Copy it somewhere safe, off the box. See [State & backups](#state--backups).

---

## Using it

> **Prefer not to type flags?** Run **`creator-server menu`** (or just
> `creator-server` on a terminal) for a full-screen console that drives the whole
> lifecycle: first-run setup, **server controls** (start/stop/restart, logs,
> health, TLS-cert status), register/rotate/remove configs, mint + burn share
> links, direct `.npvs` handout, and backup — all from one screen. The steps
> below are the scriptable equivalents.

### 1. Register your config

You already have a working config **in the app** — the one pointing at your VPN
server. You don't re-type it here in any special format: the app hands you the
config as a string, and you paste it in.

1. In the app, open the config you want to distribute and choose
   **Export → "Copy for creator-server"** — it copies one config string.
2. Register it (paste the string):
   ```sh
   creator-server config add -state-dir /var/lib/creator-server -config "<paste>"
   ```
   On a terminal you can run `config add` with no `-config` and it prompts you
   to paste. It prints a **`configId`** — the handle you hand out in step 2 —
   and appends the entry to `<state-dir>/configs.json`, which the running server
   **hot-reloads** (no restart).

See what's registered any time:

```sh
creator-server config ls -state-dir /var/lib/creator-server
```

The server returns this config **verbatim** to recipients — it never mints,
derives, or rewrites the secrets inside it. Because the app produces the
string, you never touch the config's field layout.

> **Advanced.** `config add` also accepts raw config JSON (`-config '{…}'` or
> `-config-file f.json`) and can build a v2ray entry from flags
> (`-server -port -address -password`). A per-entry `configTtlSec` (60s–7d,
> default 1h) sets the app's re-fetch cadence.

### 2. Hand out the config

Both ways below give the recipient a *pointer*, not the config. Pick by how you
reach your audience:

**A. Share link — public channel / many people.** Mint a token for the
`configId` from step 1 and post the link:

```sh
creator-server mint-share-link \
  -state-dir /var/lib/creator-server \
  -config-id <configId> \
  -redemption-url https://issuer.yourdomain.example/v1/redeem \
  -redemptions 100 -expires-in 168h        # 168h = 7 days; 0 = no expiry
```

It prints a `npvtunnel://join?u=…&t=…` link. Post it; recipients tap once and
their app sets itself up. (`-label "telegram-main"` tags redemptions in your
audit log so you can tell which channel a leak came from.) Review live tokens
with `creator-server token ls -state-dir /var/lib/creator-server`.

**B. Direct — when you already have someone's device pubkey.** They copy their
device's public key from the app and send it to you. Mint a `.npvs` pointer for
the same `configId`:

```sh
creator-server mint \
  -state-dir /var/lib/creator-server \
  -config-id <configId> \
  -recipient-pubkey <theirDevicePubkey-base64url> \
  -issuer-url https://issuer.yourdomain.example/v1/issue \
  -out recipient.npvs
```

For several people, repeat `-recipient-pubkey` or give a comma-separated list
(`-recipient-pubkey A,B,C`), or pass `-recipient-pubkeys-file`. Send each person
the `.npvs` file (any channel — it carries no config, just the pointer).

### 3. Burn a leaked share link

If a `npvtunnel://join` link you posted is being passed around more widely than
you intended, kill it so no new people can redeem it:

```sh
creator-server revoke-token -state-dir /var/lib/creator-server -token <token>
```

Further redemption attempts get `404`. Configs already fetched through past
redemptions keep working until they expire — so keep TTLs short. To rotate the
underlying technique, change your VPN server + `configs.json` and re-issue.

---

## Tuning (optional)

Defaults work out of the box. Skip this unless you're managing a closed
audience.

### Attestation tiers

`attestationPolicy` controls how the server treats devices:

| Mode | Behavior |
|---|---|
| `off` (default) | Ignore attestation. |
| `observe` | Log what the client claimed; never block. |
| `soft` | Serve everyone, but make unattested devices re-fetch sooner (`softFailureTtlSec`, default 300s). |
| `strict` | Reject devices that can't produce a Play Integrity / App Attest token. |

For real hardware checks, name a `verifier` and opt into gates:

```json
"attestationPolicy": {
  "mode": "strict",
  "verifier": "android-key-attestation",
  "requireHardwareBacked": true,
  "requireTrustedRoot": true,
  "requireVerifiedBoot": true
}
```

This anchors the device's attestation chain at Google's roots (bundled in the
binary — no Google Cloud account needed); the three `require*` gates reject
emulators, self-signed chains, and rooted/unlocked devices. `apple-app-attest`
is the iOS equivalent (set `appId` to `TEAMID.bundle.id`; don't set
`requireVerifiedBoot` — iOS doesn't expose it).

> **⚠ Audience-fit warning.** Do **not** enable `strict` / `requireVerifiedBoot`
> for sideload-heavy audiences. Many users in censored regions run rooted phones
> *by necessity*, and these gates lock them out. They're for managed audiences
> where everyone is on stock firmware. Open audiences should leave attestation
> `off` and rely on short re-fetch cadences + your own data-plane rotation.

### Rate limit

The issuer **always** caps how many configs one device fetches per config per
hour — `30/h` by default, even with attestation off. The cap is keyed on the
**device key, not the source IP**, so users sharing one carrier / CGNAT
address aren't collectively throttled. `maxIssuancesPerHour` (on
`attestationPolicy`) raises it for a config. Over-limit requests get `429` with
`Retry-After`. The public `/v1/redeem` endpoint additionally has a per-IP limit
(30/h), and the server sheds load with `503` past a concurrency cap.

---

## Operating it

### State & backups

With `-state-dir` set, the server keeps these files (`0600`, owner `creator`):

| File | What it is | Lose it and… |
|---|---|---|
| `creator-key.pem` | Your identity — the signing key recipients pin | every recipient must re-import. **Back up.** |
| `audit-salt.bin` | Salt that hashes device IDs in the audit log | log correlation resets (nothing cryptographic). |
| `configs.json` | The configs you hand out — **you write this** | nothing to hand out. |
| `redemption-tokens.json` | Live share-link tokens — **managed by the subcommands** | outstanding links stop working. |

Back the whole directory up in one step with `creator-server backup
-state-dir <dir>` — it writes a single `.tar.gz`; store it off the box.

Without `-state-dir` the server runs with ephemeral keys and serves a stub
config — **dev/test only**, since every restart breaks recipients.

Both `configs.json` and `redemption-tokens.json` are **hot-reloaded** on
change, so `config add` / `mint-share-link` take effect without a restart.

### The reverse-proxy / rate-limit gotcha

The per-IP rate limit on redemptions needs each client's real IP:

- **Behind a reverse proxy:** set `-trusted-proxy` to the proxy's CIDR (e.g.
  `-trusted-proxy 127.0.0.1/32`), or everyone collapses onto the proxy's IP.
- **Directly on the internet:** leave `-trusted-proxy` empty, so
  `X-Forwarded-For` is ignored and clients can't spoof their rate-limit key.

### Audit logs

Each handout emits one structured log line with **no raw device IDs, no
attestation tokens, no IPs, no secrets** — device IDs are salted-hashed
(`devicePkHash`) so a leaked log can't expose your recipient list. Fields:
`event`, `devicePkHash`, `configId`, `claimedPlatform`, `tokenPresent`,
`policyMode`, `ttlSec`. Route the output through journald or a file +
`logrotate`, with short retention.

> Honest limit: the salt lives on the same disk as the log, so a **full VPS
> seizure** (log + salt together) can re-identify devices. The hashing defends
> against a leaked log *file*, not against someone taking the whole machine.

### The VPN-server contract

This server doesn't run your tunnel and has no access to your data plane. It
hands out the static config you wrote in `configs.json`, **verbatim** — the
same config that already works against your VPN server. Keeping that config
working (authoring it, and replacing it in `configs.json` when your server
changes) is your job; this server only distributes it, gated by your policy.

What this server adds on top of just posting the config publicly: the handout is
gated by your attestation / rate-limit policy, and every response carries a
receipt signed by `creator-key.pem` that the app verifies before using the
config. To bound the blast radius of a leak, keep your data-plane secrets cheap
to rotate and use short `configTtlSec` re-fetch cadences so recipients pick
up a rotation quickly.

The server is a single instance; rate-limit counters are in-memory and
per-process.

---

## Trust & verification

- **No central infrastructure.** It talks only to your own VPN server and the
  clients that connect — no phone-home, no outbound calls.
- **No per-creator cloud accounts.** Google's and Apple's attestation roots are
  bundled into the binary (`attestation-roots/`).
- **Reproducible, signed releases.** Release binaries and the container image
  are built in CI and **cosign-signed** (keyless / Sigstore). Verify any
  download — even one from a mirror or a friend — against the signing identity;
  the installer does this automatically when `cosign` is present. Commands in
  [RELEASING.md](RELEASING.md#how-users-verify-a-download).
- **The protocol is implemented right here** — read the handlers in
  [`server.go`](server.go) and [`redeem.go`](redeem.go).

---

## Reference

### CLI flags (server)

| Flag | Default | Purpose |
|---|---|---|
| `-addr` | `:8443` | Bind address. |
| `-state-dir` | (none) | Persistent state directory. Empty = ephemeral/stub mode (dev/test only). |
| `-public-issuer-url` | (none) | This server's externally-reachable `/v1/issue` URL. Required for redemptions (auto-derived from `-domain`). |
| `-domain` | (none) | Public hostname for **built-in HTTPS** via Let's Encrypt — no reverse proxy. Serves `:443`, ACME on `:80`, derives `-public-issuer-url`. |
| `-acme-email` | (none) | Contact email for the Let's Encrypt account (use with `-domain`). |
| `-acme-staging` | `false` | Use Let's Encrypt staging while testing the ACME flow. |
| `-cert` / `-key` | (none) | TLS cert/key PEM (manual cert). If empty and no `-domain`, serves plain HTTP (front it with a proxy). |
| `-trusted-proxy` | (none) | CIDRs of trusted reverse proxies for `X-Forwarded-For`. Auto-defaults to localhost on a loopback bind (see above). |
| `-debug` | `false` | Verbose logging. |

### Subcommands

Run any with `-h` for full flags.

| Command | Purpose | Key flags |
|---|---|---|
| (none) | Run the server — or, on an interactive terminal, open the console. | the table above |
| `menu` | **Interactive console** — drives the whole lifecycle: setup wizard, server controls (start/stop/restart, logs, health, cert), register/rotate/remove configs, mint + burn share links, direct `.npvs` handout, backup. Bare `creator-server` on a terminal opens it. | `-state-dir` |
| `service` | Root helper the console + `install.sh` shell into so the systemd unit has **one** generator: `install` (write unit), `enable-now`, `start`/`stop`/`restart`, `status`, `logs`. | `install -tls -domain [-acme-email]`; `logs -n` |
| `init` | Guided first-run setup for scripts (state dir, key, TLS choice, next steps). The console's wizard is the friendlier equivalent. | `-state-dir`, `-domain`, `-tls`, `-acme-email` |
| `config add` / `config ls` | Register a config (paste the app's export string) / list registered configs. | `-state-dir`, `-config` (the app's export string); or `-config-file` / quick-build flags |
| `token ls` / `token revoke` | List share-link tokens with status / burn one. | `-state-dir`, `-token` |
| `status` | Snapshot: creator pubkey, #configs, #live tokens. | `-state-dir` |
| `backup` | Bundle the state dir (key + salt + configs + tokens) into one `.tar.gz`. | `-state-dir`, `-out` |
| `mint` | Make a discovery pointer (`.npvs`) for known recipient pubkey(s). | `-state-dir`, `-config-id`, `-recipient-pubkey` (repeatable / comma-list) / `-recipient-pubkeys-file`, `-issuer-url`, `-out` |
| `mint-share-link` | Make a `npvtunnel://join` link + redemption token. | `-state-dir`, `-config-id`, `-redemption-url`, `-redemptions`, `-expires-in`, `-label` |
| `revoke-token` | Burn a leaked share-link token. | `-state-dir`, `-token` |
| `version` | Print build version. | — |

### Endpoints

| Endpoint | Purpose |
|---|---|
| `POST /v1/issue` | Return your `configs.json` config verbatim, gated by your policy and signed. Called by the app to (re-)fetch the config. |
| `POST /v1/redeem` | Turn a share-link token into a per-recipient discovery pointer (not the config). |
| `GET /v1/creator-pubkey` | The creator's public signing key (dev/test; recipients pin it from the pointer). |
| `GET /healthz` | Liveness probe (`ok`). |

---

## Build & contribute

```sh
go build -o creator-server .   # Go 1.25+, single static binary, no runtime deps
go test ./...                  # issue / redeem / attestation / rate-limit suite
```

For local manual testing, run against a scratch `-state-dir` with no `-cert` and
`curl` the endpoints over `http://localhost:8443/v1/...`. Release and download-
verification details are in [RELEASING.md](RELEASING.md).

## License

[Apache-2.0](LICENSE) — see also [NOTICE](NOTICE). Open by design, so anyone can
audit it and build their own.
