# docker/ctf-re/Dockerfile
FROM python:3.12-slim@sha256:090ba77e2958f6af52a5341f788b50b032dd4ca28377d2893dcf1ecbdfdfe203

LABEL description="CTF Reverse Engineering Tools - radare2, binwalk, and more"

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    git \
    wget \
    curl \
    unzip \
    binwalk \
    file \
    wabt \
    meson \
    ninja-build \
    pkg-config \
    # JDK 21 required by Ghidra 11.2+/12.x (headless analysis + PyGhidra JVM bridge)
    openjdk-21-jdk-headless \
    && rm -rf /var/lib/apt/lists/*

# Install rizin from source (not packaged for Debian slim; meson build)
RUN git clone --depth 1 --branch v0.8.2 https://github.com/rizinorg/rizin.git /tmp/rizin \
    && meson setup --buildtype=release /tmp/rizin/build /tmp/rizin \
    && ninja -C /tmp/rizin/build \
    && ninja -C /tmp/rizin/build install \
    && ldconfig \
    && rm -rf /tmp/rizin

# NOTE: radare2 is NOT installed here — rizin (the maintained fork, built above) covers
# RE in this image, and radare2/r2 are routed to ctf-pwn. This keeps ctf-re smaller and
# avoids the dangling-symlink issue of radare2's sys/install.sh.

# --- Ghidra 12.1 (pinned) for headless analysis + PyGhidra warm-JVM bridge (UPGRADE_PLAN §6a) ---
# Version is pinned deliberately: PyGhidra is tightly coupled to the Ghidra build.
ENV GHIDRA_VERSION=12.1
ENV GHIDRA_RELEASE=ghidra_12.1_PUBLIC_20260513
ENV GHIDRA_INSTALL_DIR=/opt/ghidra
ENV JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64
RUN wget --tries=3 --retry-connrefused --timeout=60 -O /tmp/ghidra.zip \
      https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/${GHIDRA_RELEASE}.zip \
    && unzip -q /tmp/ghidra.zip -d /opt \
    # extracted dir is ghidra_<ver>_PUBLIC; resolve it dynamically rather than assuming the exact name
    && mv /opt/ghidra_*_PUBLIC ${GHIDRA_INSTALL_DIR} \
    && rm /tmp/ghidra.zip \
    && chmod +x ${GHIDRA_INSTALL_DIR}/support/analyzeHeadless \
    && test -x ${GHIDRA_INSTALL_DIR}/support/analyzeHeadless

# Create a real account for the non-root run user (uid 1000) with a writable HOME.
# Two reasons:
#  1. Ghidra LaunchSupport writes ~/.config/ghidra at runtime (else JVM fails).
#  2. capa/vivisect call getpwuid(1000); without a passwd entry that raises
#     KeyError: 'getpwuid(): uid not found: 1000' and capa aborts.
ENV HOME=/home/ctf
RUN useradd -u 1000 -m -d /home/ctf -s /bin/sh ctf 2>/dev/null || true \
    && mkdir -p /home/ctf/.config/ghidra && chown -R 1000:1000 /home/ctf

# Install Python packages (pyghidra pinned to the Ghidra 12.1 line; capa/floss for RE triage)
RUN pip install --no-cache-dir \
    r2pipe \
    rzpipe \
    angr \
    uncompyle6 \
    pyghidra==3.1.0 \
    flare-capa==9.4.0 \
    flare-floss==3.1.1

# capa ships NO embedded rules/signatures when pip-installed — fetch the matching
# rule set (v9.4.0) and FLIRT signatures so run_capa works out of the box.
ENV CAPA_RULES=/opt/capa-rules
ENV CAPA_SIGS=/opt/capa-sigs
RUN git clone --depth 1 --branch v9.4.0 https://github.com/mandiant/capa-rules.git ${CAPA_RULES} \
    && git clone --depth 1 https://github.com/mandiant/capa.git /tmp/capa \
    && mkdir -p ${CAPA_SIGS} \
    && cp -r /tmp/capa/sigs/* ${CAPA_SIGS}/ 2>/dev/null || true \
    && rm -rf /tmp/capa \
    && chmod -R a+rX ${CAPA_RULES} ${CAPA_SIGS}

# Bake the Ghidra headless postScript (decompile dump for the run_ghidra MCP tool).
ENV GHIDRA_SCRIPTS=/opt/ghidra-scripts
COPY docker/ctf-re/scripts/ghidra_dump.py ${GHIDRA_SCRIPTS}/ghidra_dump.py
# Warm-JVM PyGhidra broker (persistent interactive session; see ghidra_session.py).
COPY docker/ctf-re/scripts/ghidra_broker.py /opt/ghidra_broker.py

# A small wrapper so the MCP tool can invoke a stable `ghidra` command that runs
# analyzeHeadless with our dump script. Args: <binary> [extra analyzeHeadless args].
RUN printf '#!/bin/sh\n\
set -e\n\
BIN="$1"; shift || true\n\
PROJ=$(mktemp -d)\n\
"$GHIDRA_INSTALL_DIR/support/analyzeHeadless" "$PROJ" tmpproj \\\n\
  -import "$BIN" -scriptPath "$GHIDRA_SCRIPTS" \\\n\
  -postScript ghidra_dump.py -deleteProject "$@"\n\
rm -rf "$PROJ"\n' > /usr/local/bin/ghidra \
    && chmod +x /usr/local/bin/ghidra

# Set workspace
WORKDIR /workspace

CMD ["/bin/bash"]
