# docker/ctf-crypto/Dockerfile
FROM python:3.12-slim@sha256:090ba77e2958f6af52a5341f788b50b032dd4ca28377d2893dcf1ecbdfdfe203

LABEL description="CTF Crypto Tools - Hash cracking and cryptographic analysis"

# Install system dependencies
# Install system dependencies (incl. build deps for fpylll + flatter lattice tooling)
RUN apt-get update && apt-get install -y \
    build-essential \
    git \
    wget \
    curl \
    cmake \
    pkg-config \
    john \
    openssl \
    gnupg \
    libgmp-dev \
    libmpfr-dev \
    libmpc-dev \
    libfplll-dev \
    libeigen3-dev \
    libblas-dev \
    liblapack-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Python packages (lattice: fpylll; plus RSA/number-theory toolset).
# cysignals MUST be installed before fpylll (fpylll imports it at runtime).
RUN pip install --no-cache-dir cython cysignals
RUN pip install --no-cache-dir \
    pycryptodome \
    cryptography \
    z3-solver \
    gmpy2 \
    rsa \
    ecdsa \
    sympy \
    fpylll \
    factordb-pycli

# flatter (fast LLL/BKZ lattice reduction) - build from source (keeganryan/flatter)
RUN git clone --depth 1 https://github.com/keeganryan/flatter.git /tmp/flatter \
    && cmake -S /tmp/flatter -B /tmp/flatter/build \
    && cmake --build /tmp/flatter/build -j"$(nproc)" \
    && cmake --install /tmp/flatter/build \
    && ldconfig \
    && rm -rf /tmp/flatter

# RsaCtfTool - automated RSA attack toolkit (modern pyproject install).
# `pip install .` creates the `RsaCtfTool` console entrypoint on PATH.
RUN git clone --depth 1 https://github.com/RsaCtfTool/RsaCtfTool.git /opt/RsaCtfTool \
    && pip install --no-cache-dir /opt/RsaCtfTool

# --- SageMath note ---
# SageMath is NOT installed here. Per UPGRADE_PLAN.md §6 it lives in its own
# dedicated image (docker/ctf-sage/Dockerfile, ~2.5GB) so this image stays lean.
# The run_sage MCP tool targets ctftoolkit/ctf-sage (lazy-built on first use,
# prunable when idle). For SMT/constraint/algebraic problems, run_z3 (z3-solver
# above) is lighter and covers most CTF crypto needs.

# Non-root run user (uid 1000) with passwd entry + writable HOME (getpwuid fix).
ENV HOME=/home/ctf
RUN useradd -u 1000 -m -d /home/ctf -s /bin/sh ctf 2>/dev/null || true \
    && mkdir -p /home/ctf && chown -R 1000:1000 /home/ctf

# Set workspace
WORKDIR /workspace

CMD ["/bin/bash"]
