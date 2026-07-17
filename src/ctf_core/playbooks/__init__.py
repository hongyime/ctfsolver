"""Codified solver playbooks (Phase 5 — NOT RAG, per locked decision D7).

Each playbook is a small in-code record (category, trigger keywords, a markdown
workflow, and an optional Python solve skeleton) seeded from the 17-challenge
GREYCTF run. The planner matches a challenge to the best playbook and injects its
workflow + skeleton as context — deterministic, inspectable, no vector DB.

Add a playbook = append one PLAYBOOKS entry (or a module under this package).
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Playbook:
    name: str
    category: str                       # pwn / re / crypto / forensics / web / misc
    triggers: tuple[str, ...]           # keywords matched against challenge text
    workflow: str                       # markdown step-by-step
    skeleton: str = ""                  # optional starter code / commands
    tools: tuple[str, ...] = ()         # MCP tools this playbook drives

    def score(self, text: str) -> int:
        t = text.lower()
        return sum(1 for kw in self.triggers if kw.lower() in t)


# Import the seeded playbooks (kept in submodules to stay readable).
from .crypto_lattice import PLAYBOOK as _crypto_lattice  # noqa: E402
from .crypto_rsa import PLAYBOOK as _crypto_rsa          # noqa: E402
from .pwn_rop import PLAYBOOK as _pwn_rop                # noqa: E402
from .forensics_usb_hid import PLAYBOOK as _usb_hid      # noqa: E402
from .re_wasm import PLAYBOOK as _re_wasm                # noqa: E402
from .forensics_stego import PLAYBOOK as _stego          # noqa: E402
from .web_sqli import PLAYBOOK as _web_sqli              # noqa: E402

PLAYBOOKS: tuple[Playbook, ...] = (
    _crypto_lattice, _crypto_rsa, _pwn_rop, _usb_hid, _re_wasm, _stego, _web_sqli,
)


def match_playbook(challenge_text: str, category: str | None = None) -> Playbook | None:
    """Return the best-matching playbook for a challenge, or None.

    Scores by trigger-keyword hits; a category match adds a strong bonus so the
    right family wins ties. Returns None if nothing scores > 0.
    """
    text = challenge_text or ""
    best: Playbook | None = None
    best_score = 0
    for pb in PLAYBOOKS:
        s = pb.score(text)
        if category and pb.category == category.lower():
            s += 3
        if s > best_score:
            best, best_score = pb, s
    return best if best_score > 0 else None


def render_playbook(pb: Playbook) -> str:
    """Render a playbook as an injectable context block."""
    out = [f"# Playbook: {pb.name} ({pb.category})", "", "## Workflow", pb.workflow]
    if pb.tools:
        out += ["", "## Tools", ", ".join(pb.tools)]
    if pb.skeleton:
        out += ["", "## Solve skeleton", "```python", pb.skeleton.strip(), "```"]
    return "\n".join(out)


def list_playbooks() -> list[dict]:
    return [{"name": p.name, "category": p.category, "triggers": list(p.triggers)}
            for p in PLAYBOOKS]
