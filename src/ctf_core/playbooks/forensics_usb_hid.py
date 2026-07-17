"""forensics_usb_hid playbook — recover keystrokes/mouse from USB pcap (GREYCTF 'Grey Yuumi')."""

from . import Playbook

PLAYBOOK = Playbook(
    name="forensics_usb_hid",
    category="forensics",
    triggers=("usb", "hid", "keystroke", "keyboard", "mouse", "pcap usb", "capdata",
              "usbhid", "yuumi", "drawing", "leftover capture"),
    tools=("extract_usb_hid_pcap", "run_volatility"),
    workflow=(
        "1. Confirm it's a USB capture: `tshark -r cap.pcapng -Y usb.capdata` shows HID data.\n"
        "2. Decide keyboard vs mouse from report shapes (8-byte keyboard reports vs\n"
        "   3-byte [buttons,dx,dy] mouse reports).\n"
        "3. Run extract_usb_hid_pcap(path, mode='auto'). It returns:\n"
        "   - keystrokes: decoded typed text (with shift handling), and/or\n"
        "   - mouse_path: list of [x,y] deltas you can plot to recover a drawn flag.\n"
        "4. For mouse drawings, plot mouse_path with matplotlib to read the flag shape.\n"
        "5. For keystrokes, the flag is usually in the typed text directly."
    ),
    skeleton=(
        "# 1) extract (MCP tool): extract_usb_hid_pcap('capture.pcapng', mode='auto')\n"
        "# 2) if it's a mouse drawing, plot the path:\n"
        "import json, matplotlib\n"
        "matplotlib.use('Agg')\n"
        "import matplotlib.pyplot as plt\n"
        "data = json.loads(open('/workspace/hid.json').read())  # tool output\n"
        "xs = [p[0] for p in data['mouse_path']]\n"
        "ys = [-p[1] for p in data['mouse_path']]  # invert y for screen coords\n"
        "plt.figure(figsize=(12, 4)); plt.plot(xs, ys, lw=1)\n"
        "plt.axis('equal'); plt.savefig('/workspace/drawing.png')\n"
    ),
)
