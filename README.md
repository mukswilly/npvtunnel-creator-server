# creator-server

**A small config-distribution server for NpvTunnel's share-link method.**

NpvTunnel users connect to VPN servers — v2ray and SSH — that
creators run themselves. **This is not one of those.** This is a little
optional helper that does just one thing: it's one of the ways a creator hands
a config to their users — the **share-link** way.

You run it (on a cheap VPS) only if you want users to get your config by
**tapping a link** instead of you sending them a config file. When someone taps
your link, this server gives their app the config — and it builds that config
**fresh each time the app connects**, so the config never sits inside the file
or link you posted publicly, and a leaked credential is short-lived and bound to
the one device that fetched it.

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
            └─ config, which is built on the spot: your config + a short-lived
               credential bound to that one device.
```

So:

- **The link/file you post contains no config** — just a pointer to this server.
- **The real config is fetched per-connection**, valid ~1h, tied to one device.
  A leaked copy expires fast and, because the credential is bound to the
  device that fetched it, can't be replayed from anywhere else.

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

Shape: this binary on `127.0.0.1:8443`, an HTTPS reverse proxy in front, a
backed-up state directory.

1. **Provision** a small VPS (~$5/mo, `amd64` or `arm64`) and point a domain at
   it (e.g. `issuer.yourdomain.example`). This is separate from your VPN
   server(s).
2. **Install** with the one-liner above.
3. **Set your domain** in the unit:
   ```sh
   sudo sed -i 's#https://CHANGE_ME.example/v1/issue#https://issuer.yourdomain.example/v1/issue#' \
     /etc/systemd/system/creator-server.service
   ```
4. **Terminate TLS** in front of `127.0.0.1:8443` (Caddy gives automatic HTTPS):
   ```
   issuer.yourdomain.example {
       reverse_proxy 127.0.0.1:8443
   }
   ```
   Behind a proxy, also pass `-trusted-proxy 127.0.0.1/32` — see
   [the rate-limit gotcha](#the-reverse-proxy--rate-limit-gotcha).
5. **Start it:**
   ```sh
   sudo systemctl enable --now creator-server
   curl -sS http://127.0.0.1:8443/healthz   # → ok
   ```
6. **⚠ Back up your keys.** First run generates `creator-key.pem` and
   `vpn-hmac-key.bin` in the state dir. **Losing them breaks every recipient.**
   Copy them somewhere safe, off the box. See [State & backups](#state--backups).

---

## Using it

### 1. Write your config

Configs live in `<state-dir>/configs.json`. Each entry pairs a stable 16-byte
`configId` with the config you want to hand out — pointing at **your** VPN
server — and marks where the per-connection credential goes with the sentinel
**`$NPVT_CREDENTIAL$`**. The server replaces that sentinel with a fresh,
device-bound credential each time an app connects.

```json
[
  {
    "configId": "base64url-no-pad of 16 random bytes",
    "credentialEncoding": "uuid-v4",
    "config": {
      "name": "My config",
      "address": "vpn.yourdomain.example:443",
      "type": "V2RAY",
      "v2rayProfile": {
        "server": "vpn.yourdomain.example",
        "serverPort": "443",
        "password": "$NPVT_CREDENTIAL$"
      }
    }
  }
]
```

- **`config`** is a complete **v2ray** or **SSH** config — the only two protocols
  NpvTunnel supports. `config.type` (`V2RAY` or `SSH`) picks which; everything
  else (server address, port, transport settings) is just that protocol's normal
  fields. Mark the credential slot with `$NPVT_CREDENTIAL$` — `v2rayProfile.password`
  above, or `sshConfig.sshPassword` for an SSH config.
- **`credentialEncoding`**: `uuid-v4` for VLESS/VMess id fields, or
  `base64url-raw` (the default) for SSH passwords / opaque secrets.
- **`credTtlSec`** *(optional)*: how long each issued credential stays valid,
  in seconds. Omit (or `0`) for the default of **3600** (1 hour). Must be
  between **60** and **604800** (7 days). Shorter means recipients re-issue
  more often but a leaked credential dies sooner; longer is friendlier on a
  flaky/censored network. Independent of `attestationPolicy` — set it even in
  the default `off` mode. (Under `soft` mode, an unattested device's
  credential is capped at the shorter of this and `softFailureTtlSec`.)
- Restart the server after editing `configs.json` (no hot-reload).

`creator-server mint` (below) prints a fresh `configId` and a ready-to-paste
`configs.json` entry, so you don't have to hand-build one.

### 2. Hand out the config

Both ways below give the recipient a *pointer*, not the config. Pick by how you
reach your audience:

**A. Share link — public channel / many people.** Mint a token for a registered
`configId` and post the link:

```sh
creator-server mint-share-link \
  -state-dir /var/lib/creator-server \
  -config-id <configId> \
  -redemption-url https://issuer.yourdomain.example/v1/redeem \
  -redemptions 100 -expires-in 168h        # 168h = 7 days; 0 = no expiry
```

It prints a `npvtunnel://join?u=…&t=…` link. Post it; recipients tap once and
their app sets itself up. (`-label "telegram-main"` tags redemptions in your
audit log so you can tell which channel a leak came from.)

**B. Direct — when you already have someone's device pubkey.** They copy it from
the app (*My device ID*) and send it to you:

```sh
creator-server mint \
  -state-dir /var/lib/creator-server \
  -recipient-pubkey <theirDevicePubkey-base64url> \
  -issuer-url https://issuer.yourdomain.example/v1/issue \
  -out recipient.npvs
```

For several people, repeat `-recipient-pubkey` or give it a comma-separated
list (`-recipient-pubkey A,B,C`) — or pass `-recipient-pubkeys-file` with one
pubkey per line. It prints the `configId` and a `configs.json` template;
register that entry, then send each person the `.npvs` file (any channel — it
has no config in it).

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
| `soft` | Serve everyone, but give a shorter credential to unattested devices (`softFailureTtlSec`, default 300s). |
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
> `off` and rely on short credential TTLs + device-bound credentials.

### Rate limit

`maxIssuancesPerHour` (on `attestationPolicy`) caps how many configs one device
fetches per config per hour. Unlimited when no policy is set; 10/h once any
policy is configured. Over-limit requests get `429` with `Retry-After`.

---

## Operating it

### State & backups

With `-state-dir` set, the server keeps these files (`0600`, owner `creator`):

| File | What it is | Lose it and… |
|---|---|---|
| `creator-key.pem` | Your identity — the signing key recipients pin | every recipient must re-import. **Back up.** |
| `vpn-hmac-key.bin` | Shared secret with your VPN server | active sessions reconnect. **Back up.** |
| `audit-salt.bin` | Salt that hashes device IDs in the audit log | log correlation resets (nothing cryptographic). |
| `configs.json` | The configs you hand out — **you write this** | nothing to hand out. |
| `redemption-tokens.json` | Live share-link tokens — **managed by the subcommands** | outstanding links stop working. |

Without `-state-dir` the server runs with ephemeral keys and serves a stub
config — **dev/test only**, since every restart breaks recipients.

`configs.json` is read at startup (restart after editing).
`redemption-tokens.json` is re-read on each redemption, so `mint-share-link`
takes effect without a restart.

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

This server doesn't run your tunnel — it builds configs that your **own** VPN
server validates. The credential in each config is:

```
HMAC-SHA256(vpn-hmac-key, "v1.cred|" + devicePk + "|" + expiresAt)
```

(then encoded per `credentialEncoding`). Pre-share `vpn-hmac-key.bin` with your
VPN server and have it recompute that HMAC over the connecting device + expiry
and compare. **That binding is what makes a leaked credential useless from
another device** — without it on your VPN server, the credential is just a
static secret. Wiring that into your v2ray/SSH data plane is your job and is
intentionally out of scope here.

The server is a single instance; rate-limit counters and the credential cache
are in-memory and per-process.

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
| `-public-issuer-url` | (none) | This server's externally-reachable `/v1/issue` URL. Required for redemptions. |
| `-cert` / `-key` | (none) | TLS cert/key PEM. If empty, serves plain HTTP (front it with a proxy). |
| `-trusted-proxy` | (none) | CIDRs of trusted reverse proxies for `X-Forwarded-For` (see above). |
| `-debug` | `false` | Verbose logging. |

### Subcommands

Run any with `-h` for full flags.

| Command | Purpose | Key flags |
|---|---|---|
| (none) | Run the server. | the table above |
| `mint` | Make a discovery pointer (`.npvs`) for known recipient pubkey(s). | `-state-dir`, `-recipient-pubkey` (repeatable / comma-list) / `-recipient-pubkeys-file`, `-issuer-url`, `-out` |
| `mint-share-link` | Make a `npvtunnel://join` link + redemption token. | `-state-dir`, `-config-id`, `-redemption-url`, `-redemptions`, `-expires-in`, `-label` |
| `revoke-token` | Burn a leaked share-link token. | `-state-dir`, `-token` |
| `version` | Print build version. | — |

### Endpoints

| Endpoint | Purpose |
|---|---|
| `POST /v1/issue` | Build the config for one connection: your `configs.json` template with a fresh device-bound credential, signed. Called by the app on every connect. |
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
