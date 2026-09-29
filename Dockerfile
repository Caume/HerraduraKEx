# HerraduraKEx quickstart image (TODO #139).
#
# Builds and runs FIVE of the suite's seven language targets — C, Go, Python,
# ARM Thumb-2 (via arm-linux-gnueabi-gcc + qemu-arm) and NASM i386 (via nasm/ld
# + qemu-i386) — without requiring the user to install any cross-toolchain
# locally.  Two are excluded ON PURPOSE, and both reasons are now CHECKED by
# tools/check_docker_mirror.py rather than merely written here:
#
#   Arduino — needs arduino-cli plus a board target, so it is not a
#             host-portable build at all (excluded since TODO #139).
#   JAVA    — the bindings/java port is complete (TODO #196-#203) and is a
#             REQUIRED CI job, but this image installs no JDK: default-jdk-headless
#             roughly doubles it, and that port's own CliTest scripts are
#             Java-vs-Python interop, which needs no cross-toolchain and so gains
#             nothing from a container.  THIS LINE IS THE POINT OF TODO #326 --
#             until then this header advertised a language count it did not
#             build, and named neither Java nor a reason for omitting it, which
#             is the drift ci.yml's "CI and the scripts can't silently drift
#             apart" had promised could not happen.
#
# This Dockerfile intentionally does not duplicate build logic: it installs
# the dependencies each build_*.sh script's own header comments document,
# then defers to those scripts (and CLAUDE.md's Build/Testing sections) for
# everything else, so the two can't drift apart silently.
#
# Build:  docker build -t herradurakex .
# Run:    docker run --rm -it herradurakex
#         (runs build_c.sh, build_go.sh, build_arm.sh, build_asm_i386.sh,
#          then the C/Go/Python test suites and one CLI integration test as
#          a smoke test — see docker-entrypoint.sh)
#
# Pinned to linux/amd64: Ubuntu's arm64 repos do not carry an arm64->armel
# cross-toolchain, only amd64->armel, which is also the pairing
# build_arm.sh's own header comments were written against. On a non-amd64
# Docker host (e.g. Apple Silicon, an ARM dev machine), building this image
# needs QEMU user-mode emulation registered with binfmt_misc — the same
# category of qemu dependency this project's own ARM/i386 targets already
# require, just at the container level instead of the binary level. Most
# Docker Desktop installs register this automatically; on Linux:
#   sudo apt-get install -y docker-buildx qemu-user-binfmt
#   docker buildx build --platform linux/amd64 --load -t herradurakex .
# ARG rather than a literal, so buildkit's FromPlatformFlagConstDisallowed lint
# is satisfied and a caller can retarget without editing the file; the default
# keeps the amd64 pinning the paragraph above argues for.
ARG TARGET_PLATFORM=linux/amd64
FROM --platform=${TARGET_PLATFORM} ubuntu:24.04

# Dependencies, one apt-get per source they're documented in:
#   build_c.sh          -> gcc (libc6-dev pulls in the C headers/libc gcc needs;
#                           Ubuntu's --no-install-recommends gcc package omits it)
#   build_go.sh          -> golang-go
#   build_arm.sh          -> gcc-arm-linux-gnueabi, libc6-dev-armel-cross (the
#                           crt1.o/headers cross-dev package; build_arm.sh's
#                           own comment names the runtime-only libc6-armel-cross,
#                           which is not sufficient to link a static ELF)
#   build_asm_i386.sh    -> nasm, binutils-x86-64-linux-gnu (elf_i386-capable
#                           ld on ARM64 hosts; harmless extra on x86_64)
#   run_arm.sh/run_asm_i386.sh -> qemu-user (qemu-arm, qemu-i386)
#   CliTest/*.sh          -> bash, python3 (already present via golang-go's
#                           and gcc's own deps, listed explicitly for clarity)
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        gcc \
        libc6-dev \
        golang-go \
        gcc-arm-linux-gnueabi \
        libc6-dev-armel-cross \
        nasm \
        binutils-x86-64-linux-gnu \
        qemu-user \
        python3 \
        bash \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /herradurakex
COPY . .

RUN chmod +x build_c.sh build_go.sh build_arm.sh build_asm_i386.sh \
             run_arm.sh run_asm_i386.sh docker-entrypoint.sh

ENTRYPOINT ["./docker-entrypoint.sh"]
