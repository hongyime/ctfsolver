# docker/ctf-pwn/Dockerfile
FROM python:3.12-slim@sha256:090ba77e2958f6af52a5341f788b50b032dd4ca28377d2893dcf1ecbdfdfe203

LABEL description="CTF Pwn Tools - Binary exploitation toolkit"

# Install system dependencies
RUN dpkg --add-architecture i386 && apt-get update && apt-get install -y \
    build-essential \
    meson \
    ninja-build \
    pkg-config \
    git \
    wget \
    curl \
    gdb \
    gdbserver \
    vim \
    tmux \
    strace \
    ltrace \
    file \
    checksec \
    socat \
    nasm \
    patchelf \
    # 32-bit / multilib support for i386 challenges
    gcc-multilib \
    libc6-dev-i386 \
    libc6-i386 \
    # ruby for one_gadget / seccomp-tools gems; libseccomp-dev for seccomp-tools
    ruby \
    ruby-dev \
    libseccomp-dev \
    && rm -rf /var/lib/apt/lists/*

# one_gadget + seccomp-tools (Ruby gems)
RUN gem install --no-document one_gadget seccomp-tools

# pwninit: prebuilt release binary (avoids the slow Rust toolchain build)
RUN wget -qO /usr/local/bin/pwninit \
      https://github.com/io12/pwninit/releases/download/3.3.1/pwninit \
    && chmod +x /usr/local/bin/pwninit

# Install radare2 from official repository
# Install radare2 from source. Use meson install (copies binaries to /usr/local);
# the legacy sys/install.sh symlinks into the build dir, which breaks once we rm it.
RUN git clone --depth 1 https://github.com/radareorg/radare2.git /tmp/radare2 \
    && meson setup --prefix=/usr/local --buildtype=release /tmp/radare2/build /tmp/radare2 \
    && ninja -C /tmp/radare2/build \
    && ninja -C /tmp/radare2/build install \
    && ldconfig \
    && rm -rf /tmp/radare2

# Install Python packages
RUN pip install --no-cache-dir \
    pwntools \
    angr \
    ropgadget \
    ropper \
    unicorn \
    keystone-engine \
    capstone \
    requests

# Non-root run user (uid 1000) with a passwd entry + writable HOME. Without a passwd
# entry, tools that call getpwuid(1000) (capa, some pwntools/angr paths) raise
# KeyError: 'getpwuid(): uid not found: 1000'.
ENV HOME=/home/ctf
RUN useradd -u 1000 -m -d /home/ctf -s /bin/sh ctf 2>/dev/null || true \
    && mkdir -p /home/ctf && chown -R 1000:1000 /home/ctf

# Set workspace
WORKDIR /workspace

# Default command
CMD ["/bin/bash"]
