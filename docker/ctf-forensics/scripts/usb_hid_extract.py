#!/usr/bin/env python3
"""USB HID pcap extractor (baked into ctf-forensics image).

Extracts keyboard keystrokes and mouse movements from a USB-capture pcap, the
classic CTF forensics pattern (e.g. GREYCTF "Grey Yuumi"). Uses tshark to pull
the HID interrupt-transfer data field (usb.capdata / usbhid.data), then decodes:

  * Keyboard: 8-byte HID reports -> characters via the USB HID usage-ID table
    (with left/right shift handling).
  * Mouse: report bytes -> relative dx/dy deltas, emitted as a path you can plot
    to recover a drawn flag.

Usage:
    usb_hid_extract.py <capture.pcap> [--mode auto|keyboard|mouse]

Output: JSON to stdout: {"mode":..., "keystrokes":"...", "mouse_path":[[x,y],...]}.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys

# USB HID keyboard usage IDs -> (unshifted, shifted)
HID_KEYS = {
    0x04: ("a", "A"), 0x05: ("b", "B"), 0x06: ("c", "C"), 0x07: ("d", "D"),
    0x08: ("e", "E"), 0x09: ("f", "F"), 0x0A: ("g", "G"), 0x0B: ("h", "H"),
    0x0C: ("i", "I"), 0x0D: ("j", "J"), 0x0E: ("k", "K"), 0x0F: ("l", "L"),
    0x10: ("m", "M"), 0x11: ("n", "N"), 0x12: ("o", "O"), 0x13: ("p", "P"),
    0x14: ("q", "Q"), 0x15: ("r", "R"), 0x16: ("s", "S"), 0x17: ("t", "T"),
    0x18: ("u", "U"), 0x19: ("v", "V"), 0x1A: ("w", "W"), 0x1B: ("x", "X"),
    0x1C: ("y", "Y"), 0x1D: ("z", "Z"),
    0x1E: ("1", "!"), 0x1F: ("2", "@"), 0x20: ("3", "#"), 0x21: ("4", "$"),
    0x22: ("5", "%"), 0x23: ("6", "^"), 0x24: ("7", "&"), 0x25: ("8", "*"),
    0x26: ("9", "("), 0x27: ("0", ")"),
    0x28: ("\n", "\n"), 0x29: ("[ESC]", "[ESC]"), 0x2A: ("[BS]", "[BS]"),
    0x2B: ("\t", "\t"), 0x2C: (" ", " "),
    0x2D: ("-", "_"), 0x2E: ("=", "+"), 0x2F: ("[", "{"), 0x30: ("]", "}"),
    0x31: ("\\", "|"), 0x33: (";", ":"), 0x34: ("'", "\""), 0x35: ("`", "~"),
    0x36: (",", "<"), 0x37: (".", ">"), 0x38: ("/", "?"),
}


def _tshark_capdata(pcap: str) -> list[str]:
    """Return the list of hex HID data payloads from the pcap via tshark."""
    # Try the common field names in order; different captures expose different ones.
    for field in ("usbhid.data", "usb.capdata"):
        try:
            out = subprocess.run(
                ["tshark", "-r", pcap, "-Y", f"{field}", "-T", "fields", "-e", field],
                capture_output=True, text=True, timeout=300,
            )
            rows = [r.strip().replace(":", "") for r in out.stdout.splitlines() if r.strip()]
            if rows:
                return rows
        except (subprocess.SubprocessError, FileNotFoundError):
            continue
    return []


def decode_keyboard(rows: list[str]) -> str:
    out = []
    for hexstr in rows:
        try:
            data = bytes.fromhex(hexstr)
        except ValueError:
            continue
        if len(data) < 3:
            continue
        modifier = data[0]
        keycode = data[2]
        if keycode == 0:
            continue
        shifted = bool(modifier & 0x22)  # left (0x02) or right (0x20) shift
        pair = HID_KEYS.get(keycode)
        if pair:
            out.append(pair[1] if shifted else pair[0])
    return "".join(out)


def decode_mouse(rows: list[str]) -> list[list[int]]:
    x, y = 0, 0
    path = []
    for hexstr in rows:
        try:
            data = bytes.fromhex(hexstr)
        except ValueError:
            continue
        if len(data) < 3:
            continue
        # Byte layout commonly: [buttons, dx, dy]; deltas are signed int8.
        dx = data[1] - 256 if data[1] > 127 else data[1]
        dy = data[2] - 256 if data[2] > 127 else data[2]
        x += dx
        y += dy
        path.append([x, y])
    return path


def main() -> int:
    ap = argparse.ArgumentParser(description="Extract USB HID keystrokes/mouse from a pcap.")
    ap.add_argument("pcap", help="path to the USB capture pcap/pcapng")
    ap.add_argument("--mode", choices=["auto", "keyboard", "mouse"], default="auto")
    args = ap.parse_args()

    rows = _tshark_capdata(args.pcap)
    if not rows:
        print(json.dumps({"error": "no USB HID data found (usbhid.data / usb.capdata)"}))
        return 1

    result: dict = {"reports": len(rows)}
    if args.mode in ("auto", "keyboard"):
        result["keystrokes"] = decode_keyboard(rows)
    if args.mode in ("auto", "mouse"):
        result["mouse_path"] = decode_mouse(rows)
    result["mode"] = args.mode
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
