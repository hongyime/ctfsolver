# CTF Toolkit - General Purpose Security Tools
FROM kalilinux/kali-rolling:latest

LABEL maintainer="CTF Toolkit"
LABEL description="General purpose security tools for CTF challenges"

# Update and install common security tools.
# NOTE: Kali base is intentionally NOT digest-pinned (kali-rolling apt repo moves;
# a stale digest desyncs from the package index and breaks apt-get install).
RUN apt-get update && apt-get install -y \
    nmap \
    sqlmap \
    nikto \
    gobuster \
    ffuf \
    hydra \
    exploitdb \
    whatweb \
    wafw00f \
    sslscan \
    masscan \
    netcat-traditional \
    dnsutils \
    whois \
    curl \
    wget \
    git \
    python3 \
    python3-pip \
    python3-venv \
    expat \
    # --- Phase 0: web/recon tools that were mapped in docker_runner but missing here ---
    feroxbuster \
    httpx-toolkit \
    amass \
    assetfinder \
    wfuzz \
    # --- Phase 0: OSINT tools (dockerized; replaces host-subprocess osint_tools.py) ---
    spiderfoot \
    theharvester \
    # --- Phase 1: web tools ---
    nuclei \
    && rm -rf /var/lib/apt/lists/*

# Install additional Python tools
RUN pip3 install --break-system-packages \
    requests \
    beautifulsoup4 \
    lxml \
    urllib3 \
    pycryptodome \
    xmltodict

# jwt_tool (JWT analysis/attacks) - clone + deps (not packaged in Kali)
RUN git clone --depth 1 https://github.com/ticarpi/jwt_tool.git /opt/jwt_tool \
    && pip3 install --break-system-packages -r /opt/jwt_tool/requirements.txt \
    && printf '#!/bin/sh\nexec python3 /opt/jwt_tool/jwt_tool.py "$@"\n' > /usr/local/bin/jwt_tool \
    && chmod +x /usr/local/bin/jwt_tool

# Non-root run user (uid 1000) with passwd entry + writable HOME (getpwuid fix;
# also where nuclei stores its templates).
ENV HOME=/home/ctf
RUN useradd -u 1000 -m -d /home/ctf -s /bin/sh ctf 2>/dev/null || true \
    && mkdir -p /home/ctf && chown -R 1000:1000 /home/ctf

# Bake the nuclei templates by cloning the official repo directly (deterministic;
# `nuclei -update-templates` is flaky/needs version-sync and silently fetches nothing
# in a headless build). nuclei reads templates from ~/nuclei-templates by default.
RUN git clone --depth 1 https://github.com/projectdiscovery/nuclei-templates.git \
      /home/ctf/nuclei-templates \
    && chown -R 1000:1000 /home/ctf/nuclei-templates

# Set workspace directory
WORKDIR /workspace

# Default command
CMD ["/bin/bash"]
