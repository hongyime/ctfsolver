# docker/ctf-forensics/Dockerfile
FROM python:3.12-slim@sha256:090ba77e2958f6af52a5341f788b50b032dd4ca28377d2893dcf1ecbdfdfe203

LABEL description="CTF Forensics Tools - Memory, disk, and network forensics"

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    git \
    wget \
    curl \
    exiftool \
    tshark \
    sleuthkit \
    foremost \
    binwalk \
    steghide \
    zip \
    sox \
    libsox-fmt-all \
    # ruby for the zsteg gem
    ruby \
    ruby-dev \
    && rm -rf /var/lib/apt/lists/*

# zsteg (PNG/BMP LSB steganalysis) - Ruby gem
RUN gem install --no-document zsteg

# stegseek (fast steghide bruteforce) - prebuilt .deb release
RUN wget -q -O /tmp/stegseek.deb \
      https://github.com/RickdeJager/stegseek/releases/download/v0.6/stegseek_0.6-1.deb \
    && (dpkg -i /tmp/stegseek.deb || apt-get update && apt-get install -y -f) \
    && rm -f /tmp/stegseek.deb && rm -rf /var/lib/apt/lists/*

# Install Python packages (volatility3 mem forensics; PIL/scapy/numpy).
# NOTE: no reliable headless `sstv` PyPI package exists; SSTV/audio-stego is handled
# via sox spectrogram (run_sox_spectrogram tool) + PIL, which is more universal.
RUN pip install --no-cache-dir \
    volatility3 \
    pillow \
    scapy \
    numpy

# Bake the USB-HID pcap extractor (keystrokes/mouse recovery; e.g. Grey Yuumi).
COPY docker/ctf-forensics/scripts/usb_hid_extract.py /usr/local/bin/usb_hid_extract
RUN chmod +x /usr/local/bin/usb_hid_extract

# Non-root run user (uid 1000) with passwd entry + writable HOME (getpwuid fix).
ENV HOME=/home/ctf
RUN useradd -u 1000 -m -d /home/ctf -s /bin/sh ctf 2>/dev/null || true \
    && mkdir -p /home/ctf && chown -R 1000:1000 /home/ctf

# Set workspace
WORKDIR /workspace

CMD ["/bin/bash"]
