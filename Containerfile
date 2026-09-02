# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

FROM --platform=$BUILDPLATFORM docker.io/library/golang:1.26.7-bookworm@sha256:e8c859f5632dcfde7b32d2012b4351728f6437930887c2f6a91ea242459e5514 AS build
ARG TARGETOS=linux
ARG TARGETARCH
ARG OWNTRANSIT_VERSION=dev
ARG OWNTRANSIT_RELEASE_ID=unreleased
ARG OWNTRANSIT_SOURCE_COMMIT=unknown
ARG OWNTRANSIT_SOURCE_DIRTY=unknown
ARG SOURCE_DATE_EPOCH=1
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY LICENSE THIRD_PARTY_NOTICES.md RELEASE_MANIFEST.example.json ./
COPY cmd ./cmd
COPY internal ./internal
COPY scripts/release/releasectl ./scripts/release/releasectl
RUN set -eu; \
    export CGO_ENABLED=0 GOOS="$TARGETOS" GOARCH="$TARGETARCH"; \
    build_ldflags="-buildid= -s -w -X github.com/sentrybottale/owntransit/internal/buildinfo.Version=${OWNTRANSIT_VERSION} -X github.com/sentrybottale/owntransit/internal/buildinfo.Release=${OWNTRANSIT_RELEASE_ID} -X github.com/sentrybottale/owntransit/internal/buildinfo.Commit=${OWNTRANSIT_SOURCE_COMMIT} -X github.com/sentrybottale/owntransit/internal/buildinfo.Dirty=${OWNTRANSIT_SOURCE_DIRTY}"; \
    go build -mod=readonly -trimpath -buildvcs=false -ldflags="$build_ldflags" -o /out/owntransit-relay ./cmd/owntransit-relay; \
    go build -mod=readonly -trimpath -buildvcs=false -ldflags="$build_ldflags" -o /out/owntransit-connector ./cmd/owntransit-connector; \
    go build -mod=readonly -trimpath -buildvcs=false -tags=owntransit_poc_ssh -ldflags="$build_ldflags" -o /out/owntransit-connector-poc ./cmd/owntransit-connector; \
    go build -mod=readonly -trimpath -buildvcs=false -ldflags="$build_ldflags" -o /out/owntransit ./cmd/owntransit; \
    go build -mod=readonly -trimpath -buildvcs=false -ldflags="$build_ldflags" -o /out/owntransit-launcher ./cmd/owntransit-launcher; \
    go build -mod=readonly -trimpath -buildvcs=false -ldflags="$build_ldflags" -o /out/owntransitctl ./cmd/owntransitctl; \
    go build -mod=readonly -trimpath -buildvcs=false -ldflags="$build_ldflags" -o /out/owntransit-provision ./cmd/owntransit-provision; \
    go build -mod=readonly -trimpath -buildvcs=false -ldflags='-buildid= -s -w' -o /out/owntransit-poc-certgen ./cmd/owntransit-poc-certgen; \
    go build -mod=readonly -trimpath -buildvcs=false -tags=owntransit_poc_ssh -ldflags='-buildid= -s -w' -o /out/owntransit-poc-certgen-poc ./cmd/owntransit-poc-certgen; \
    touch -d "@${SOURCE_DATE_EPOCH}" /out/*

# Local exporters consume this target with explicit TARGETOS/TARGETARCH build
# arguments. Release staging selects only the exact supported artifact matrix;
# the extra POC binaries remain development inputs, not release rows.
FROM scratch AS release-files
COPY --from=build /out/ /

# Verification uses a second source stage on the requested target platform.
# This prevents an arm64 workstation from silently running arm64 tests while
# merely cross-compiling linux/amd64 release artifacts.
FROM --platform=$TARGETPLATFORM docker.io/library/golang:1.26.7-bookworm@sha256:e8c859f5632dcfde7b32d2012b4351728f6437930887c2f6a91ea242459e5514 AS linux-amd64-verify
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
RUN set -eu; \
    test "$TARGETOS/$TARGETARCH" = linux/amd64; \
    test "$(go env GOOS)/$(go env GOARCH)" = linux/amd64
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY LICENSE THIRD_PARTY_NOTICES.md RELEASE_MANIFEST.example.json ./
COPY cmd ./cmd
COPY internal ./internal
COPY scripts/release/releasectl ./scripts/release/releasectl

FROM linux-amd64-verify AS test
RUN go test -mod=readonly -race ./...

FROM linux-amd64-verify AS test-poc
RUN go test -mod=readonly -race -tags=owntransit_poc_ssh ./...

# Transitional stage alias for older local automation. The ordinary test stage
# is now the production port-22 profile.
FROM test AS test-native

FROM linux-amd64-verify AS vet
RUN set -eu; \
    files=$(gofmt -l cmd internal scripts/release/releasectl); \
    test -z "$files" || { printf '%s\n' "$files" >&2; exit 1; }; \
    go vet -mod=readonly ./...; \
    go vet -mod=readonly -tags=owntransit_poc_ssh ./...

FROM linux-amd64-verify AS vulncheck
ARG GOVULNCHECK_VERSION=v1.1.4
RUN set -eu; \
    GOBIN=/tmp/govulncheck-bin go install "golang.org/x/vuln/cmd/govulncheck@${GOVULNCHECK_VERSION}"; \
    /tmp/govulncheck-bin/govulncheck ./...; \
    /tmp/govulncheck-bin/govulncheck -tags=owntransit_poc_ssh ./...

FROM linux-amd64-verify AS dependency-licenses
COPY .dockerignore Containerfile ./
COPY scripts/security-check.sh ./scripts/security-check.sh
COPY scripts/tests/dependency-licenses.sh ./scripts/tests/dependency-licenses.sh
COPY scripts/release/make-relay-oci.sh ./scripts/release/make-relay-oci.sh
COPY scripts/release/releasectl ./scripts/release/releasectl
RUN /bin/sh ./scripts/tests/dependency-licenses.sh --full

FROM scratch AS relay
COPY --from=build /out/owntransit-relay /owntransit-relay
COPY --from=build /src/LICENSE /licenses/Apache-2.0.txt
COPY --from=build /src/THIRD_PARTY_NOTICES.md /licenses/THIRD_PARTY_NOTICES.md
USER 65532:65532
ENTRYPOINT ["/owntransit-relay"]
CMD ["run", "--runtime-root=/runtime", "--anchor-view-root=/anchor", "--reader-gid=65532"]

FROM scratch AS connector
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/owntransit-connector /owntransit-connector
USER 65532:65532
ENTRYPOINT ["/owntransit-connector"]

FROM scratch AS connector-native
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/owntransit-connector /owntransit-connector
USER 65532:65532
ENTRYPOINT ["/owntransit-connector"]

FROM scratch AS client
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/owntransit /owntransit
USER 65532:65532
ENTRYPOINT ["/owntransit"]

FROM scratch AS lifecycle
COPY --from=build /out/owntransitctl /owntransitctl
USER 65532:65532
ENTRYPOINT ["/owntransitctl"]

FROM scratch AS provisioner
COPY --from=build /out/owntransit-provision /owntransit-provision
USER 65532:65532
ENTRYPOINT ["/owntransit-provision"]

FROM scratch AS certgen
COPY --from=build /out/owntransit-poc-certgen /owntransit-poc-certgen
USER 65532:65532
ENTRYPOINT ["/owntransit-poc-certgen"]

FROM scratch AS certgen-native
COPY --from=build /out/owntransit-poc-certgen /owntransit-poc-certgen
USER 65532:65532
ENTRYPOINT ["/owntransit-poc-certgen"]

FROM scratch AS certgen-poc
COPY --from=build /out/owntransit-poc-certgen-poc /owntransit-poc-certgen
USER 65532:65532
ENTRYPOINT ["/owntransit-poc-certgen"]

# Apple Container gives each container its own lightweight VM, so a separate
# sshd container cannot share the connector's loopback. This POC-only target
# co-locates a loopback-only sshd. The production connector target above stays
# shell-free, non-root, and contains no SSH host key.
FROM docker.io/library/debian:bookworm-slim@sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171 AS connector-poc
RUN export DEBIAN_FRONTEND=noninteractive; \
    apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates openssh-server util-linux \
    && rm -rf /var/lib/apt/lists/* \
    && rm -f /etc/ssh/ssh_host_*_key /etc/ssh/ssh_host_*_key.pub \
    && useradd --uid 65532 --no-create-home --shell /usr/sbin/nologin owntransit \
    && useradd --uid 1000 --create-home --shell /bin/bash owntransit-poc \
    && passwd -d owntransit-poc \
    && install -d -m 0755 /run/sshd
COPY --from=build /out/owntransit-connector-poc /usr/local/bin/owntransit-connector
COPY deploy/poc/sshd_config /etc/ssh/sshd_config_owntransit
COPY --chmod=0755 deploy/poc/connector-poc-entrypoint.sh /usr/local/bin/connector-poc-entrypoint
ENTRYPOINT ["/usr/local/bin/connector-poc-entrypoint"]
