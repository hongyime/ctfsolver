"""Rotating IAM access key pool for Bedrock-backed container spawns.

Reads a pool file (default ~/.opencode/bedrock-iam-key-pool.json) containing
verified AWS IAM access keys, each of which can be used for direct Bedrock
SigV4 calls. When the harness spawns a per-challenge container that needs
Bedrock access (kiro, opencode), it selects a key from the pool so multiple
concurrent challenges don't share a single identity's rate limit.

Selection strategy: hash the challenge slug + agent name and modulo by the
pool size. Same challenge+agent always gets the same key (deterministic
resumption); different (challenge, agent) pairs distribute across keys.

The pool file is NEVER read into memory beyond the current process — each
docker_command build re-reads it fresh so key rotations (from the mint helper)
are picked up without needing a harness restart.

Pool file schema:
    {
      "region": "ap-southeast-1",
      "test_model": "...",
      "keys": [
        {
          "label": "BedrockAPIKey-4e9d",
          "access_key_id": "AKIA...",
          "secret_access_key": "...",
          "arn": "arn:aws:iam::709609992277:user/BedrockAPIKey-4e9d",
          "account": "709609992277",
          "bedrock_ok": true
        },
        ...
      ]
    }
"""
from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path


DEFAULT_POOL_PATH = Path.home() / ".opencode" / "bedrock-iam-key-pool.json"


@dataclass(frozen=True)
class IamKey:
    label: str
    access_key_id: str
    secret_access_key: str
    account: str
    arn: str
    bedrock_ok: bool


def pool_path() -> Path:
    override = os.environ.get("CTF_HARNESS_IAM_KEY_POOL")
    return Path(override).expanduser() if override else DEFAULT_POOL_PATH


def load_pool() -> list[IamKey]:
    """Load the pool from disk. Returns [] if the file is missing or malformed.

    Only returns keys where bedrock_ok is True (or missing — treated as
    optimistic-ok for user-authored pools).
    """
    p = pool_path()
    if not p.exists():
        return []
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return []
    keys = data.get("keys") or []
    out: list[IamKey] = []
    for k in keys:
        if not (k.get("access_key_id") and k.get("secret_access_key")):
            continue
        # Skip keys that were explicitly verified as non-working.
        if k.get("bedrock_ok") is False:
            continue
        out.append(
            IamKey(
                label=str(k.get("label") or k["access_key_id"][:8]),
                access_key_id=str(k["access_key_id"]),
                secret_access_key=str(k["secret_access_key"]),
                account=str(k.get("account") or ""),
                arn=str(k.get("arn") or ""),
                bedrock_ok=bool(k.get("bedrock_ok", True)),
            )
        )
    return out


def pool_region() -> str:
    """Region for Bedrock calls, from pool file or fallback env / default."""
    p = pool_path()
    if p.exists():
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
            if data.get("region"):
                return str(data["region"])
        except Exception:
            pass
    return os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION") or "ap-southeast-1"


def select_key_for(challenge_slug: str, agent: str, keys: list[IamKey] | None = None) -> IamKey | None:
    """Pick a stable key from the pool for this (challenge, agent) tuple.

    Deterministic: same challenge_slug+agent always gets the same key so
    resumes hit the same identity. Different pairs spread across the pool.
    """
    if keys is None:
        keys = load_pool()
    if not keys:
        return None
    h = hashlib.sha256(f"{challenge_slug}|{agent}".encode("utf-8")).digest()
    idx = int.from_bytes(h[:4], "big") % len(keys)
    return keys[idx]
