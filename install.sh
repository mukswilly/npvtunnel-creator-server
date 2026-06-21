#!/bin/sh
# npvtunnel-creator-server installer.
#
# Downloads a signed release binary, verifies its checksum (and cosign
# signature when cosign is present), installs it to /usr/local/bin, and — when
# run as root — sets up the `creator` user, state directory, and a systemd
# unit. No Go toolchain required.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/mukswilly/npvtunnel-creator-server/main/install.sh | sh
#   # or, having reviewed it first:
#   sh install.sh [--version vX.Y.Z] [--no-service]
#                 [--builtin-tls issuer.yourdomain.example [--acme-email you@x.com]]
#
#   --builtin-tls DOMAIN  configure the systemd unit so the binary terminates
#                         TLS itself via Let's Encrypt — no reverse proxy.
#                         Needs ports 80+443 free and DNS for DOMAIN here.
#   --acme-email EMAIL    contact address for the Let's Encrypt account.
#
# Environment:
#   VERSION       release tag to install (default: latest)
#   INSTALL_DIR   binary destination (default: /usr/local/bin)
#   STATE_DIR     state directory (default: /var/lib/creator-server)
set -eu

REPO="mukswilly/npvtunnel-creator-server"
BIN="creator-server"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
STATE_DIR="${STATE_DIR:-/var/lib/creator-server}"
VERSION="${VERSION:-}"
NO_SERVICE=0
BUILTIN_TLS_DOMAIN="${BUILTIN_TLS_DOMAIN:-}"
ACME_EMAIL="${ACME_EMAIL:-}"

while [ $# -gt 0 ]; do
  case "$1" in
    --version) VERSION="$2"; shift 2 ;;
    --version=*) VERSION="${1#*=}"; shift ;;
    --no-service) NO_SERVICE=1; shift ;;
    --builtin-tls) BUILTIN_TLS_DOMAIN="$2"; shift 2 ;;
    --builtin-tls=*) BUILTIN_TLS_DOMAIN="${1#*=}"; shift ;;
    --acme-email) ACME_EMAIL="$2"; shift 2 ;;
    --acme-email=*) ACME_EMAIL="${1#*=}"; shift ;;
    -h|--help) sed -n '2,24p' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

err() { echo "install: $*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

have curl || have wget || err "need curl or wget"
have tar || err "need tar"
fetch() { # fetch URL OUTFILE
  if have curl; then curl -fsSL "$1" -o "$2"; else wget -qO "$2" "$1"; fi
}
fetch_stdout() { if have curl; then curl -fsSL "$1"; else wget -qO- "$1"; fi; }

# ---- platform detection ----
os="$(uname -s | tr '[:upper:]' '[:lower:]')"
[ "$os" = "linux" ] || err "this installer supports Linux servers only (got: $os)"
case "$(uname -m)" in
  x86_64|amd64) arch="amd64" ;;
  aarch64|arm64) arch="arm64" ;;
  *) err "unsupported architecture: $(uname -m) (amd64 and arm64 are published)" ;;
esac

# ---- resolve version ----
if [ -z "$VERSION" ]; then
  VERSION="$(fetch_stdout "https://api.github.com/repos/${REPO}/releases/latest" \
    | grep '"tag_name"' | head -1 | sed -E 's/.*"tag_name": *"([^"]+)".*/\1/')"
  [ -n "$VERSION" ] || err "could not determine latest version; pass --version vX.Y.Z"
fi
echo "install: ${BIN} ${VERSION} (linux/${arch})"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
base="https://github.com/${REPO}/releases/download/${VERSION}"
tarball="${BIN}_${VERSION#v}_linux_${arch}.tar.gz"

fetch "${base}/${tarball}" "${tmp}/${tarball}" || err "download failed: ${base}/${tarball}"
fetch "${base}/checksums.txt" "${tmp}/checksums.txt" || err "download failed: checksums.txt"

# ---- verify checksum ----
( cd "$tmp"
  if have sha256sum; then
    grep " ${tarball}\$" checksums.txt | sha256sum -c - >/dev/null \
      || err "checksum mismatch for ${tarball}"
  elif have shasum; then
    grep " ${tarball}\$" checksums.txt | shasum -a 256 -c - >/dev/null \
      || err "checksum mismatch for ${tarball}"
  else
    err "need sha256sum or shasum to verify the download"
  fi )
echo "install: checksum OK"

# ---- verify cosign signature (best-effort) ----
if have cosign; then
  fetch "${base}/checksums.txt.sig" "${tmp}/checksums.txt.sig" || err "missing signature"
  fetch "${base}/checksums.txt.pem" "${tmp}/checksums.txt.pem" || err "missing certificate"
  cosign verify-blob \
    --certificate "${tmp}/checksums.txt.pem" \
    --signature "${tmp}/checksums.txt.sig" \
    --certificate-identity-regexp "^https://github.com/${REPO}/" \
    --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
    "${tmp}/checksums.txt" >/dev/null 2>&1 \
    && echo "install: signature OK (cosign)" \
    || err "cosign signature verification FAILED — do not run this binary"
else
  echo "install: cosign not found — skipping signature check (checksum verified)."
  echo "         Install cosign for full supply-chain verification:"
  echo "         https://docs.sigstore.dev/cosign/system_config/installation/"
fi

tar -xzf "${tmp}/${tarball}" -C "$tmp"
[ -f "${tmp}/${BIN}" ] || err "binary ${BIN} not found in archive"

# ---- install binary ----
SUDO=""
if [ "$(id -u)" -ne 0 ]; then
  if have sudo; then SUDO="sudo"; else
    echo "install: not root and no sudo — placing binary in ./ instead of ${INSTALL_DIR}"
    cp "${tmp}/${BIN}" "./${BIN}"; chmod +x "./${BIN}"
    echo "install: done. Move ./${BIN} to a directory on your PATH."
    exit 0
  fi
fi
$SUDO install -m 0755 "${tmp}/${BIN}" "${INSTALL_DIR}/${BIN}"
echo "install: binary -> ${INSTALL_DIR}/${BIN}"
"${INSTALL_DIR}/${BIN}" version || true

# ---- service setup (root only) ----
if [ "$NO_SERVICE" -eq 1 ]; then exit 0; fi
if ! have systemctl; then
  echo "install: systemd not found — binary installed, set up your own service manager."
  exit 0
fi

# Dedicated unprivileged user.
if ! id creator >/dev/null 2>&1; then
  $SUDO useradd --system --no-create-home --shell /usr/sbin/nologin creator 2>/dev/null \
    || $SUDO useradd --system --no-create-home --shell /sbin/nologin creator 2>/dev/null || true
fi
$SUDO install -d -m 0700 -o creator -g creator "$STATE_DIR"

# Built-in TLS vs reverse-proxy mode: the ExecStart line and the
# capabilities differ. Built-in TLS binds privileged ports 80+443, so the
# unprivileged 'creator' user needs CAP_NET_BIND_SERVICE.
if [ -n "$BUILTIN_TLS_DOMAIN" ]; then
  EMAIL_FLAG=""
  [ -n "$ACME_EMAIL" ] && EMAIL_FLAG=" -acme-email ${ACME_EMAIL}"
  EXEC_START="${INSTALL_DIR}/${BIN} -state-dir ${STATE_DIR} -domain ${BUILTIN_TLS_DOMAIN}${EMAIL_FLAG}"
  CAP_BOUND="CapabilityBoundingSet=CAP_NET_BIND_SERVICE"
  CAP_AMBIENT="AmbientCapabilities=CAP_NET_BIND_SERVICE"
else
  EXEC_START="${INSTALL_DIR}/${BIN} -addr 127.0.0.1:8443 -state-dir ${STATE_DIR} -public-issuer-url https://CHANGE_ME.example/v1/issue"
  CAP_BOUND="CapabilityBoundingSet="
  CAP_AMBIENT="AmbientCapabilities="
fi

unit="/etc/systemd/system/creator-server.service"
$SUDO sh -c "cat > '$unit'" <<EOF
[Unit]
Description=NpvTunnel creator-server (issuer + share-link redemption)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=creator
Group=creator
ExecStart=${EXEC_START}
Restart=on-failure
RestartSec=2
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
RestrictAddressFamilies=AF_INET AF_INET6
ReadWritePaths=${STATE_DIR}
${CAP_BOUND}
${CAP_AMBIENT}

[Install]
WantedBy=multi-user.target
EOF
$SUDO systemctl daemon-reload
echo "install: systemd unit -> ${unit}"

if [ -n "$BUILTIN_TLS_DOMAIN" ]; then
cat <<EOF

Next steps (built-in TLS for ${BUILTIN_TLS_DOMAIN}):
  1. Point ${BUILTIN_TLS_DOMAIN}'s DNS A/AAAA record at this server.
  2. Make sure ports 80 and 443 are open (see hardening below).
  3. Start it:
       sudo systemctl enable --now creator-server
       sudo journalctl -u creator-server -n 20 --no-pager
  4. BACK UP your signing key once generated:
       sudo -u creator ${INSTALL_DIR}/${BIN} backup -state-dir ${STATE_DIR}

Register a config, then mint a share link:
  sudo -u creator ${INSTALL_DIR}/${BIN} config add -state-dir ${STATE_DIR}
  sudo -u creator ${INSTALL_DIR}/${BIN} mint-share-link -state-dir ${STATE_DIR} --help
EOF
else
cat <<EOF

Next steps (reverse-proxy TLS):
  1. Edit ${unit} — set -public-issuer-url to your domain
     (e.g. https://issuer.yourname.example/v1/issue).
  2. Put a TLS-terminating reverse proxy (Caddy/nginx) in front of
     127.0.0.1:8443, e.g. Caddy:
       issuer.yourname.example { reverse_proxy 127.0.0.1:8443 }
     (Or re-run this installer with --builtin-tls <domain> to skip the proxy.)
  3. Start it:
       sudo systemctl enable --now creator-server
       sudo journalctl -u creator-server -n 20 --no-pager
  4. BACK UP your signing key once generated:
       sudo -u creator ${INSTALL_DIR}/${BIN} backup -state-dir ${STATE_DIR}

Register a config, then mint a share link:
  sudo -u creator ${INSTALL_DIR}/${BIN} config add -state-dir ${STATE_DIR}
  sudo -u creator ${INSTALL_DIR}/${BIN} mint-share-link -state-dir ${STATE_DIR} --help
EOF
fi

cat <<EOF

Manage it interactively (full-screen console — register configs, mint
links, burn tokens, check status, back up):
  sudo -u creator ${INSTALL_DIR}/${BIN} menu -state-dir ${STATE_DIR}
EOF

cat <<'EOF'

Harden the box (recommended — this server enforces fairness, but a
volumetric DDoS must be absorbed at the network edge, not here):
  # Firewall: SSH + HTTP(S) only
  sudo ufw allow 22/tcp && sudo ufw allow 80/tcp && sudo ufw allow 443/tcp
  sudo ufw --force enable
  # Ban IPs that hammer the endpoint
  sudo apt-get install -y fail2ban
  # For real traffic volume, put Cloudflare's free tier in front.
EOF
