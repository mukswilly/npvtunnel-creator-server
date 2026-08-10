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
  release_json="$(fetch_stdout "https://api.github.com/repos/${REPO}/releases/latest" 2>/dev/null || true)"
  VERSION="$(printf '%s' "$release_json" | grep '"tag_name"' | head -1 | sed -E 's/.*"tag_name": *"([^"]+)".*/\1/')"
  [ -n "$VERSION" ] || err "no published release is available yet; pass --version after checking GitHub Releases"
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
if [ "$NO_SERVICE" -eq 1 ]; then
  $SUDO ln -sf "${INSTALL_DIR}/${BIN}" "${INSTALL_DIR}/npv-creator"
  echo "install: dashboard -> ${INSTALL_DIR}/npv-creator"
  exit 0
fi
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
# Upgrades may encounter state created by an older root-run unit. The dashboard
# and the hardened service both run as the dedicated creator account, so bring
# the complete existing state tree under that account before either starts.
$SUDO chown -R creator:creator "$STATE_DIR"

# Creator-facing launcher. It opens the dashboard as the dedicated account so
# creators only need `npv-creator`; the API binary and its state ownership stay
# separate from the login account used for SSH.
launcher="${INSTALL_DIR}/npv-creator"
# The launcher path may be a symlink to the API binary. Unlink the exact path
# first so writing the wrapper cannot follow it and overwrite the freshly
# installed server binary.
$SUDO unlink "$launcher" 2>/dev/null || true
$SUDO sh -c "cat > '$launcher'" <<EOF
#!/bin/sh
set -eu
server_bin='${INSTALL_DIR}/${BIN}'
state_dir='${STATE_DIR}'
if [ "\$(id -un)" = creator ]; then
  exec "\$server_bin" __dashboard -state-dir "\$state_dir"
fi
if [ "\$(id -u)" -eq 0 ]; then
  if command -v runuser >/dev/null 2>&1; then
    exec runuser -u creator -- "\$server_bin" __dashboard -state-dir "\$state_dir"
  fi
  exec su -s /bin/sh creator -c "exec '\$server_bin' __dashboard -state-dir '\$state_dir'"
fi
exec sudo -u creator "\$server_bin" __dashboard -state-dir "\$state_dir"
EOF
$SUDO chmod 0755 "$launcher"
echo "install: dashboard -> ${launcher}"

# Narrow sudoers drop-in: the console runs as the unprivileged 'creator'
# account (so state files stay creator-owned — the binary never chowns), and
# reaches a private service-control entry point through sudo. This grants the
# creator account passwordless rights to ONLY that entry point; every unit
# it writes still runs the issuer as User=creator, so no general root power is
# conferred. It's what lets the console's setup + start/stop actions work
# without the operator juggling users.
sudoers="/etc/sudoers.d/creator-server"
$SUDO sh -c "cat > '$sudoers'" <<EOF
creator ALL=(root) NOPASSWD: ${INSTALL_DIR}/${BIN} __service *
EOF
$SUDO chmod 0440 "$sudoers"
# Reject an invalid generated drop-in before installing it.
$SUDO visudo -cf "$sudoers" >/dev/null 2>&1 || { $SUDO rm -f "$sudoers"; echo "install: sudoers drop-in failed validation, removed"; }

# Generate the systemd unit through the binary. Built-in TLS needs a domain;
# without one, defer unit creation to the console setup wizard.
unit="/etc/systemd/system/creator-server.service"
if [ -n "$BUILTIN_TLS_DOMAIN" ]; then
  EMAIL_FLAG=""
  [ -n "$ACME_EMAIL" ] && EMAIL_FLAG="-acme-email ${ACME_EMAIL}"
  $SUDO "${INSTALL_DIR}/${BIN}" __service install \
    -bin "${INSTALL_DIR}/${BIN}" -state-dir "${STATE_DIR}" \
    -tls builtin -domain "${BUILTIN_TLS_DOMAIN}" ${EMAIL_FLAG}
  $SUDO "${INSTALL_DIR}/${BIN}" __service enable-now
  echo "install: systemd unit running -> ${unit}"
cat <<EOF

Setup is complete for ${BUILTIN_TLS_DOMAIN}. Point the domain's DNS at this
server and make sure public ports 80 and 443 are open. Use npv-creator for
health, logs, configs, share links, and backups.
EOF
elif [ -f "$unit" ]; then
  # Re-render older or manually-created units through the current hardened
  # template while preserving their address, domain, TLS mode and state path.
  $SUDO "${INSTALL_DIR}/${BIN}" __service repair-existing
  $SUDO "${INSTALL_DIR}/${BIN}" __service restart
  echo "install: existing service repaired and restarted with ${VERSION}"
else
cat <<EOF

Finish setup in the console. It asks for your domain, standard HTTPS or a
CDN/reverse-proxy origin port, writes the unit, starts the service, and shows
the key to back up:
       npv-creator
EOF

  if [ -t 2 ] && [ -r /dev/tty ] && [ -w /dev/tty ]; then
    echo "install: opening first-run setup (exit the menu when finished)"
    "${INSTALL_DIR}/npv-creator" </dev/tty >/dev/tty 2>&1
  fi
fi

cat <<EOF

Manage it interactively (full-screen console — register configs, mint
links, burn tokens, check status, back up):
  npv-creator
EOF

cat <<'EOF'

For public deployments, allow only SSH and HTTP(S) through the firewall and
put the service behind a network edge capable of absorbing volumetric attacks.
EOF
