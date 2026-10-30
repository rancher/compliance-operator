# Image that provides cross compilation tooling.
FROM --platform=$BUILDPLATFORM rancher/mirrored-tonistiigi-xx:1.6.1 AS xx

# Minimal BCI base image, as recommended by RFD 0070.
FROM registry.suse.com/bci/bci-nano:16.0 AS base

# The AppCo Go image has no package manager, so the extra tools needed by
# the build (make) and by xx (file, flock, sed, grep) are installed from BCI
# base.
# Its SLE version must match the one AppCo Go is based on.
FROM --platform=$BUILDPLATFORM registry.suse.com/bci/bci-base:15.7 AS tools
RUN zypper --non-interactive refresh && \
    zypper --non-interactive --installroot /chroot install --no-recommends \
        make file sed grep util-linux

# Besides the binary, the final image only adds a nobody user/group entry,
# so that the UID it runs as (65534) resolves to a named user, as in other
# BCI images. bci-nano does not define it and has no shell to add it, so
# the files are prepared here.
FROM --platform=$BUILDPLATFORM registry.suse.com/bci/bci-base:15.7 AS user-setup
COPY --from=base /etc/group /final/etc/group
RUN echo "nobody:x:65534:" >> /final/etc/group && \
    install -dv -m 0755 /final/var/lib/nobody

# Differs from BCI, by removing /bin/bash from root:
RUN printf "root:x:0:0:root:/root:/usr/bin/false\nnobody:x:65534:65534:nobody:/var/lib/nobody:/usr/bin/false\n" > /final/etc/passwd

# Builds with the Go compiler from the AppCo Go image, as recommended by
# RFD 0070. Pinned to MAJOR.MINOR.PATCH, matching go.mod, so the toolchain
# is deterministic and bumped by Renovate.
FROM --platform=$BUILDPLATFORM registry.suse.com/rancher/appco-go:1.27.2 AS builder

COPY --from=tools /chroot /

WORKDIR /src
COPY go.sum \
     go.mod \
     Makefile \
     /src
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

COPY pkg /src/pkg
COPY hack /src/hack
COPY main.go /src

# Ensures that the binary that was built was cross-compiled correctly
# and is valid on the target platform.
COPY --from=xx / /

ARG TARGETPLATFORM
RUN xx-go --wrap && mkdir -p /run/lock

# By setting the version as an argument, we can avoid running the version logic 
# a second time (inside the Docker build process). Therefore, removing the need
# to access the .git dir.
ARG VERSION
RUN --mount=type=cache,target=/go/pkg/mod \
    VERSION=${VERSION} TARGET_BIN=/out/compliance-operator make build
RUN xx-verify --static /out/compliance-operator

FROM base AS final

COPY --from=user-setup /final/ /
COPY --from=builder /out/compliance-operator /usr/bin/compliance-operator

# Aligns nobody user ID with BCI.
USER 65534:65534

CMD ["/usr/bin/compliance-operator"]
