# CyberHunter - Panel release build image.
#
# Release binaries are compiled on the OLDEST glibc we support (Ubuntu 22.04,
# glibc 2.35), so they run on Ubuntu 22.04+ and Debian 12+ by construction.
# scripts/release-build/check-glibc.sh then refuses any binary that asks for a
# newer symbol version or links a library outside the base system.
#
# The base image is pinned by the digest of its multi-arch index, read with
# `docker buildx imagetools inspect ubuntu:22.04` when this file was written.
# The Rust toolchain is pinned to an exact version.
#
# Bump the org.cyberhunter.release-build label whenever this file (or one of
# the two scripts copied below) changes: scripts/release.sh rebuilds the image
# only when that number changes.
FROM ubuntu:22.04@sha256:9abcaffc92a5279fff3a6a41635c0800ea33e528425fb389658806476e7defde

LABEL org.cyberhunter.release-build="1"

ARG RUST_TOOLCHAIN=1.100.0
ENV DEBIAN_FRONTEND=noninteractive \
    RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# The aarch64 cross toolchain is installed unconditionally: it is the 22.04
# one (glibc 2.35 as well), and one image for both architectures means one
# label to version.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      build-essential cmake pkg-config ca-certificates curl \
      gcc-aarch64-linux-gnu libc6-dev-arm64-cross \
 && rm -rf /var/lib/apt/lists/*

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs -o /tmp/rustup-init.sh \
 && sh /tmp/rustup-init.sh -y --no-modify-path --profile minimal \
      --default-toolchain "${RUST_TOOLCHAIN}" \
 && rm -f /tmp/rustup-init.sh \
 && rustup target add --toolchain "${RUST_TOOLCHAIN}" x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu \
 && rustc --version \
 && rustc --version | grep -q "^rustc ${RUST_TOOLCHAIN} "

ENV CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc \
    CC_aarch64_unknown_linux_gnu=aarch64-linux-gnu-gcc \
    AR_aarch64_unknown_linux_gnu=aarch64-linux-gnu-ar

COPY check-glibc.sh build-in-container.sh /usr/local/bin/
RUN sed -i 's/\r$//' /usr/local/bin/check-glibc.sh /usr/local/bin/build-in-container.sh \
 && chmod 0755 /usr/local/bin/check-glibc.sh /usr/local/bin/build-in-container.sh

WORKDIR /build
