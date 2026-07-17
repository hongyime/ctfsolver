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
    gitleaks \
    golang-go \
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
    xmltodict \
    arjun \
    git-dumper \
    schemathesis

# LinkFinder is distributed as a GitHub tool, not a PyPI package.
RUN git clone --depth 1 https://github.com/GerbenJavado/LinkFinder.git /opt/LinkFinder \
    && pip3 install --break-system-packages -r /opt/LinkFinder/requirements.txt \
    && printf '#!/bin/sh\nexec python3 /opt/LinkFinder/linkfinder.py "$@"\n' > /usr/local/bin/linkfinder \
    && chmod +x /usr/local/bin/linkfinder

# GraphQL Cop's PyPI name is a placeholder; install the actual upstream CLI.
RUN git clone --depth 1 https://github.com/dolevf/graphql-cop.git /opt/graphql-cop \
    && pip3 install --break-system-packages simplejson==3.17.6 termcolor==2.2.0 \
    && printf '#!/bin/sh\nexec python3 /opt/graphql-cop/graphql-cop.py "$@"\n' > /usr/local/bin/graphql-cop \
    && chmod +x /usr/local/bin/graphql-cop

# ProjectDiscovery Katana is not consistently packaged in Kali; use the
# upstream release binary instead of compiling a large Go dependency graph.
ARG KATANA_VERSION=1.6.1
RUN wget -q -O /tmp/katana.zip \
      "https://github.com/projectdiscovery/katana/releases/download/v${KATANA_VERSION}/katana_${KATANA_VERSION}_linux_amd64.zip" \
    && python3 -c "import pathlib, zipfile; z=zipfile.ZipFile('/tmp/katana.zip'); n=next(n for n in z.namelist() if n == 'katana' or n.endswith('/katana')); pathlib.Path('/usr/local/bin/katana').write_bytes(z.read(n))" \
    && chmod +x /usr/local/bin/katana \
    && rm -f /tmp/katana.zip

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
