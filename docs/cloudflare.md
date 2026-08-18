# Deploy behind Cloudflare

Creator Server can sit behind Cloudflare without exposing its plaintext API.
Configure **Local reverse proxy or Cloudflare Tunnel** in `npv-creator`; the
service then listens only on a loopback origin such as `127.0.0.1:8443` while
recipients continue to use `https://issuer.example.com`.

Orange-cloud DNS alone is not a reverse proxy on the server. It cannot connect
to a loopback-only origin. Choose one of these topologies.

## Local Caddy or nginx

Run Caddy or nginx on the same server. It owns public ports 80 and 443 and
forwards to the loopback origin. Start from [the Caddy example](../deploy/Caddyfile.example)
or [the nginx example](../deploy/nginx.conf.example).

1. Point the hostname's DNS record at the server and enable Cloudflare proxying.
2. Keep Creator Server in proxy mode on `127.0.0.1:8443`.
3. Configure the local proxy for the same public hostname.
4. Use Cloudflare **Full (strict)** encryption. Ensure the local proxy has a
   publicly trusted certificate or a Cloudflare Origin CA certificate.
5. Permit public HTTP(S) only to the local proxy. Never expose port 8443.

The local proxy is the only peer Creator Server trusts for `X-Forwarded-For`.
Do not configure `0.0.0.0/0` or `::/0` as a trusted proxy; doing so lets clients
spoof the address used by redemption rate limits.

## Cloudflare Tunnel

Install `cloudflared` using Cloudflare's supported package and create a named
tunnel in the Cloudflare dashboard. Start from
[the tunnel example](../deploy/cloudflared.yml.example), replacing the tunnel
identifier, credentials path, and hostname. The tunnel forwards directly to
the loopback origin; no public inbound port is required.

Keep the credentials file readable only by the `cloudflared` service account.
The Creator Server installer does not install `cloudflared`, change DNS, or
handle account credentials.

## Verify the recipient path

Open **Server** in `npv-creator`:

- **Origin** checks the local loopback API.
- **Public** checks the HTTPS hostname recipients use.

Both must report `ok`. Then verify from a different network:

```sh
curl --fail --show-error https://issuer.example.com/healthz
curl --fail --show-error https://issuer.example.com/v1/creator-pubkey
```

If Origin succeeds but Public fails, inspect the Cloudflare DNS record, SSL
mode, tunnel/proxy service, firewall, and origin certificate. A local public
check may also fail on networks without DNS hairpin support, so the off-server
check is authoritative.

Creator Server requests are small JSON or binary responses and need no
WebSocket support. Preserve the request method, body, `Host`, and
`X-Forwarded-For` headers. Keep normal proxy request-size and timeout limits;
do not cache `/v1/issue`, `/v1/redeem`, or `/healthz`.
