# Releasing & verifying

## Cutting a release

Releases are tag-driven. Push a semver tag:

```sh
git tag v0.1.0
git push origin v0.1.0
```

The `release` workflow then:

1. runs `go test ./...`,
2. builds static `linux/amd64` + `linux/arm64` binaries (goreleaser),
3. writes `checksums.txt` and **cosign-signs it keylessly** (Sigstore OIDC —
   no secrets to manage),
4. publishes a GitHub Release with the archives, checksums, signature, and
   certificate,
5. builds + pushes a multi-arch image to
   `ghcr.io/mukswilly/npvtunnel-creator-server` and cosign-signs it.

No repository secrets are required — `id-token: write` (cosign) and the
built-in `GITHUB_TOKEN` (release + GHCR) cover everything.

## How users verify a download

Checksum only:

```sh
sha256sum -c checksums.txt
```

Full supply-chain (cosign):

```sh
cosign verify-blob \
  --certificate checksums.txt.pem \
  --signature checksums.txt.sig \
  --certificate-identity-regexp '^https://github.com/mukswilly/npvtunnel-creator-server/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  checksums.txt
```

Container image:

```sh
cosign verify \
  --certificate-identity-regexp '^https://github.com/mukswilly/npvtunnel-creator-server/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/mukswilly/npvtunnel-creator-server:latest
```

`install.sh` runs the blob verification automatically when `cosign` is on the
PATH.

## Censored-channel note

GitHub is blocked or risky in some regions creators operate from. The release
artifacts are small static binaries — easy to mirror or pass peer-to-peer. The
**cosign identity above is the root of trust**, independent of where the binary
came from: a creator who received the binary from a mirror or a friend can still
verify it's authentic with the commands above. Publish that identity (and any
mirror URLs) somewhere creators can reach.
