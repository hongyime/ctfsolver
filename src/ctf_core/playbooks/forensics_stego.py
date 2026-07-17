"""forensics_stego playbook — image/audio steganography."""

from . import Playbook

PLAYBOOK = Playbook(
    name="forensics_stego",
    category="forensics",
    triggers=("steg", "stego", "lsb", "steghide", "zsteg", "hidden", "image",
              "png", "jpg", "bmp", "spectrogram", "sstv", "audio", "wav", "embedded"),
    tools=("run_zsteg", "run_stegseek", "decode_stego", "run_sox_spectrogram"),
    workflow=(
        "1. Triage the file: exiftool + binwalk + strings (decode_stego / run_binary_analysis).\n"
        "   binwalk -e often pulls appended/embedded files immediately.\n"
        "2. PNG/BMP -> run_zsteg(-a) for LSB channels; JPG -> run_stegseek with a wordlist\n"
        "   (rockyou) to brute the steghide passphrase, or decode_stego with a known pass.\n"
        "3. Audio (wav/mp3) -> run_sox_spectrogram to reveal text/SSTV hidden in frequency.\n"
        "4. Check for appended archives (PK zip header), polyglots, and metadata fields.\n"
        "5. Extract the payload, recurse if it's another container, read the flag."
    ),
    skeleton=(
        "# PNG/BMP LSB:           run_zsteg('img.png', options='-a')\n"
        "# JPG steghide brute:    run_stegseek('img.jpg', wordlist='/usr/share/wordlists/rockyou.txt')\n"
        "# Known passphrase:      decode_stego('img.jpg', passphrase='secret')\n"
        "# Audio spectrogram:     run_sox_spectrogram('audio.wav', out_name='spec.png')\n"
        "# Appended/embedded:     run via binwalk -e in run_binary_analysis\n"
    ),
)
