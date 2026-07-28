# HerraduraKEx quickstart image (TODO #139).
#
# Builds and runs the full six-language build matrix — C, Go, Python, ARM
# Thumb-2 (via arm-linux-gnueabi-gcc + qemu-arm), NASM i386 (via nasm/ld +
# qemu-i386), Arduino is excluded (needs arduino-cli + a board target, not a
# host-portable build) — without requiring the user to install any
# cross-toolchain locally.
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
# cross-toolchain (no libc6-dev-armel-cross candidate), only amd64->armel,
# which is also the pairing build_arm.sh's own header comments were written
# against. On a non-amd64 Docker host (e.g. Apple Silicon, an ARM dev
# machine), building this image needs QEMU user-mode emulation registered
# with binfmt_misc — the same category of qemu dependency this project's
# own ARM/i386 targets already require, just at the container level instead
# of the binary level. Most Docker Desktop installs register this
# automatically; on Linux, see: docker run --privileged --rm
# tonistiigi/binfmt --install amd64.
FROM --platform=linux/amd64 ubuntu:24.04

# Dependencies, one apt-get per source they're documented in:
#   build_c.sh          -> gcc (libc6-dev pulls in the C headers/libc gcc needs;
#                           Ubuntu's --no-install-recommends gcc package omits it)
#   build_go.sh          -> golang-go
#   build_arm.sh          -> gcc-arm-linux-gnueabi, libc6-armel-cross
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
        libc6-armel-cross \
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
