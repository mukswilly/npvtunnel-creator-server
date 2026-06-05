# syntax=docker/dockerfile:1
#
# Multi-stage, multi-arch build for npvtunnel-creator-server.
# Standalone-buildable (`docker build .`) and used by the release workflow's
# buildx step for the published ghcr.io image. The final image is distroless
# static + nonroot, holding only the static Go binary.

FROM --platform=$BUILDPLATFORM golang:1.25 AS build
WORKDIR /src

# Cache module downloads.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=dev
ARG TARGETOS
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" \
    -o /out/creator-server .

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/creator-server /usr/local/bin/creator-server

# Persistent state (creator-key.pem, vpn-hmac-key.bin, configs.json, …).
# Mount a volume here so keys survive restarts.
VOLUME ["/var/lib/creator-server"]
EXPOSE 8443

ENTRYPOINT ["/usr/local/bin/creator-server"]
# Default to the issuer server with on-disk state. Override the CMD to run a
# subcommand (e.g. `mint-share-link …`) or to pass -public-issuer-url / -cert.
CMD ["-addr", ":8443", "-state-dir", "/var/lib/creator-server"]
