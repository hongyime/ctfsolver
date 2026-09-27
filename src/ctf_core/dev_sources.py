"""Read-only source delivery for first-party container helpers."""
from pathlib import Path

USB_HELPER = "/opt/ctf-dev/usb_hid_extract.py"
_HELPERS = {
    "ctftoolkit/ctf-forensics": [("docker/ctf-forensics/scripts/usb_hid_extract.py", USB_HELPER)],
    "ctftoolkit/ctf-re": [
        ("docker/ctf-re/scripts/ghidra_dump.py", "/opt/ghidra-scripts/ghidra_dump.py"),
        ("docker/ctf-re/scripts/ghidra_broker.py", "/opt/ghidra_broker.py"),
    ],
}

def helper_source_mounts(image: str, project_root: Path, convert=None) -> dict:
    """Use checkout sources when present; packaged installs keep image helpers.

    The checkout paths must be visible to the Docker daemon. No file contents,
    dependencies, images, or workspace data are copied or modified here.
    """
    root = project_root.resolve()
    mounts = {}
    for relative, target in _HELPERS.get(image, []):
        source = (root / relative).resolve()
        if not source.is_relative_to(root):
            raise ValueError("Helper source must stay inside the checkout")
        if not source.is_file():
            continue
        if convert is not None:
            mounts.update(convert(str(source), target, "ro"))
        else:
            mounts[str(source)] = {"bind": target, "mode": "ro"}
    return mounts
