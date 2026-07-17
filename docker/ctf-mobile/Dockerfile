FROM mcr.microsoft.com/dotnet/sdk:8.0-jammy

LABEL description="CTF Mobile and Managed-Code Reverse Engineering Tools"

ENV DEBIAN_FRONTEND=noninteractive
ENV PATH="/root/.dotnet/tools:/opt/jadx/bin:${PATH}"

ARG APKTOOL_VERSION=3.0.2
ARG JADX_VERSION=1.5.2
ARG ILSPYCMD_VERSION=9.1.0.7988

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
      ca-certificates \
      file \
      openjdk-17-jre-headless \
      python3 \
      python3-pip \
      unzip \
      wget \
    && rm -rf /var/lib/apt/lists/*

RUN wget --tries=3 --retry-connrefused --timeout=60 -O /usr/local/bin/apktool.jar \
      "https://github.com/iBotPeaches/Apktool/releases/download/v${APKTOOL_VERSION}/apktool_${APKTOOL_VERSION}.jar" \
    && printf '#!/bin/sh\nexec java -jar /usr/local/bin/apktool.jar "$@"\n' > /usr/local/bin/apktool \
    && chmod +x /usr/local/bin/apktool

RUN wget --tries=3 --retry-connrefused --timeout=60 -O /tmp/jadx.zip \
      "https://github.com/skylot/jadx/releases/download/v${JADX_VERSION}/jadx-${JADX_VERSION}.zip" \
    && mkdir -p /opt/jadx \
    && unzip -q /tmp/jadx.zip -d /opt/jadx \
    && rm /tmp/jadx.zip \
    && chmod +x /opt/jadx/bin/jadx

RUN dotnet tool install --global ilspycmd --version "${ILSPYCMD_VERSION}" \
    && pip3 install --no-cache-dir pyinstxtractor-ng uncompyle6 \
    && printf '#!/bin/sh\nexec pyinstxtractor-ng "$@"\n' > /usr/local/bin/pyinstxtractor \
    && chmod +x /usr/local/bin/pyinstxtractor

WORKDIR /workspace

CMD ["/bin/bash"]
