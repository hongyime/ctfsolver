"""Persistent PyGhidra warm-JVM session manager (mirrors gdb_session.py).

Replaces the cold per-call analyzeHeadless path (run_ghidra) with a detached
ctf-re container running /opt/ghidra_broker.py: the JVM boots once, the binary is
analyzed once, then decompile/strings/xref/import/export calls reuse that warm
program over a JSONL protocol on the attached socket.

Design reviewed by Oracle. Key points:
  * readiness: ghidra_start blocks until the broker emits {"ready": true} (JVM boot
    + auto-analysis can take minutes -> generous CTFTOOLKIT_GHIDRA_READY_TIMEOUT).
  * Docker attach_socket multiplexes with an 8-byte frame header per chunk; the
    buffered reader strips it and scans for newline-delimited JSON across frames.
  * hardened: cap_drop ALL, user 1000:1000, no-new-privileges, network_disabled,
    higher mem_limit (CTFTOOLKIT_GHIDRA_MEM, default 4g) for big programs.
  * per-session asyncio.Lock serialises requests; op timeout kills a stuck session.
  * kill-orphans-on-startup (warm JVM state can't be recovered across a restart).
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import struct
import uuid
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

RE_IMAGE = "ctftoolkit/ctf-re"
BROKER = "/opt/ghidra_broker.py"
_FRAME = 8  # docker stream header: [type(1), 0,0,0, size(4 BE)]

READY_TIMEOUT = int(os.environ.get("CTFTOOLKIT_GHIDRA_READY_TIMEOUT", "300"))
OP_TIMEOUT = int(os.environ.get("CTFTOOLKIT_GHIDRA_OP_TIMEOUT", "120"))
MEM_LIMIT = os.environ.get("CTFTOOLKIT_GHIDRA_MEM", "4g")


def _client():
    from .docker_runner import DockerRunner
    return DockerRunner().client


@dataclass
class GhidraSession:
    session_id: str
    container: Any
    sock: Any
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    buf: bytes = b""


_sessions: dict[str, GhidraSession] = {}
_REG_GUARD = asyncio.Lock()


def _raw(sock):
    """Return the low-level socket. Linux Docker wraps as sock._sock; Windows
    Docker Desktop returns an NpipeSocket that IS the socket (no ._sock)."""
    return getattr(sock, "_sock", sock)


def _read_line_blocking(sess: GhidraSession) -> str:
    """Read one newline-delimited line from the broker, stripping docker frames.

    Buffered: scans the accumulated payload for '\\n' across frame boundaries.
    """
    r = _raw(sess.sock)
    while True:
        nl = sess.buf.find(b"\n")
        if nl != -1:
            line = sess.buf[:nl]
            sess.buf = sess.buf[nl + 1:]
            return line.decode("utf-8", "replace")
        # need more data: read one frame
        while len(sess.buf) < _FRAME:
            chunk = r.recv(8192)
            if not chunk:
                raise ConnectionError("ghidra broker socket closed")
            sess.buf += chunk
        # If this looks like a docker mux frame, consume by size; else treat raw.
        size = struct.unpack(">I", sess.buf[4:8])[0]
        # Heuristic: docker frames have byte0 in {0,1,2}; otherwise assume un-muxed.
        if sess.buf[0] in (0, 1, 2) and size < 64 * 1024 * 1024:
            sess.buf = sess.buf[_FRAME:]
            while len(sess.buf) < size:
                chunk = r.recv(8192)
                if not chunk:
                    raise ConnectionError("ghidra broker socket closed mid-frame")
                sess.buf += chunk
            # leave payload in buf; loop re-scans for newline
        else:
            # not framed; keep reading raw until newline
            chunk = r.recv(8192)
            if not chunk:
                raise ConnectionError("ghidra broker socket closed")
            sess.buf += chunk


def _send_blocking(sess: GhidraSession, obj: dict) -> None:
    _raw(sess.sock).sendall((json.dumps(obj) + "\n").encode("utf-8"))


async def ghidra_start(binary: str, mem_limit: str = MEM_LIMIT) -> dict:
    """Start a warm Ghidra session on /workspace/<binary>. Blocks until analyzed."""
    client = _client()
    session_id = uuid.uuid4().hex[:12]
    name = f"ctftoolkit-ghidra-{session_id[:8]}"
    target = f"/workspace/{binary.lstrip('/')}"

    from .docker_runner import DockerRunner
    volumes = DockerRunner()._prepare_volumes()
    loop = asyncio.get_running_loop()
    try:
        container = await loop.run_in_executor(None, lambda: client.containers.run(
            image=RE_IMAGE,
            command=["python3", BROKER, target],
            name=name,
            detach=True,
            stdin_open=True,
            tty=False,
            remove=False,
            cap_drop=["ALL"],
            security_opt=["no-new-privileges:true"],
            user=os.environ.get("CTFTOOLKIT_CONTAINER_USER", "1000:1000"),
            mem_limit=mem_limit,
            network_disabled=True,
            volumes=volumes,
            environment={"GHIDRA_INSTALL_DIR": "/opt/ghidra", "HOME": "/home/ctf"},
            labels={
                "ctftoolkit.managed": "true",
                "ctftoolkit.tool": "ghidra_session",
                "ctftoolkit.session_id": session_id,
            },
        ))
    except Exception as e:
        return {"error": f"failed to start ghidra container: {e}"}

    try:
        sock = await loop.run_in_executor(None, lambda: container.attach_socket(
            params={"stdin": 1, "stdout": 1, "stderr": 0, "stream": 1}))
        try:
            _raw(sock).setblocking(True)
        except (AttributeError, OSError):
            pass  # NpipeSocket (Windows) is blocking by default
    except Exception as e:
        try:
            await loop.run_in_executor(None, lambda: container.remove(force=True))
        except Exception:
            pass
        return {"error": f"failed to attach to ghidra container: {e}"}

    sess = GhidraSession(session_id=session_id, container=container, sock=sock)

    try:
        ready = await asyncio.wait_for(
            loop.run_in_executor(None, lambda: _read_line_blocking(sess)),
            timeout=READY_TIMEOUT)
        msg = json.loads(ready)
    except asyncio.TimeoutError:
        await _kill(container)
        return {"error": f"ghidra analysis did not finish within {READY_TIMEOUT}s "
                         f"(raise CTFTOOLKIT_GHIDRA_READY_TIMEOUT or CTFTOOLKIT_GHIDRA_MEM)"}
    except Exception as e:
        await _kill(container)
        return {"error": f"ghidra broker failed before ready: {e}"}

    if not msg.get("ready"):
        await _kill(container)
        return {"error": f"ghidra broker failed: {msg.get('error')}"}

    async with _REG_GUARD:
        _sessions[session_id] = sess
    return {"session_id": session_id, "program": msg.get("program")}


async def _op(session_id: str, op: str, args: dict | None = None,
              timeout: float = OP_TIMEOUT) -> dict:
    sess = _sessions.get(session_id)
    if sess is None:
        return {"error": f"unknown ghidra session {session_id}"}
    rid = uuid.uuid4().hex[:8]
    loop = asyncio.get_running_loop()
    async with sess.lock:
        try:
            await loop.run_in_executor(None, lambda: _send_blocking(sess, {"id": rid, "op": op, "args": args or {}}))
            line = await asyncio.wait_for(
                loop.run_in_executor(None, lambda: _read_line_blocking(sess)),
                timeout=timeout)
        except asyncio.TimeoutError:
            await ghidra_stop(session_id)
            return {"error": f"ghidra op '{op}' timed out after {timeout}s; session killed"}
        except Exception as e:
            _sessions.pop(session_id, None)
            return {"error": f"ghidra session I/O error: {e}"}
    try:
        resp = json.loads(line)
    except Exception as e:
        return {"error": f"bad broker response: {e}"}
    if not resp.get("ok"):
        return {"error": resp.get("error", "unknown broker error")}
    return {"data": resp.get("data")}


async def ghidra_decompile(session_id: str, name: str = "", address: str = "") -> dict:
    args: dict = {}
    if name:
        args["name"] = name
    if address:
        args["address"] = address
    if not args:
        return {"error": "provide name or address"}
    return await _op(session_id, "decompile", args)


async def ghidra_list_functions(session_id: str) -> dict:
    return await _op(session_id, "list_functions")


async def ghidra_strings(session_id: str, min_length: int = 4, filter: str = "") -> dict:
    return await _op(session_id, "strings", {"min_length": min_length, "filter": filter})


async def ghidra_xrefs(session_id: str, name: str = "", address: str = "") -> dict:
    args: dict = {}
    if name:
        args["name"] = name
    if address:
        args["address"] = address
    return await _op(session_id, "xrefs", args)


async def ghidra_imports(session_id: str) -> dict:
    return await _op(session_id, "imports")


async def ghidra_exports(session_id: str) -> dict:
    return await _op(session_id, "exports")


async def ghidra_stop(session_id: str) -> dict:
    sess = _sessions.pop(session_id, None)
    if sess is None:
        return {"error": f"unknown ghidra session {session_id}"}
    try:
        _send_blocking(sess, {"id": "x", "op": "shutdown", "args": {}})
    except Exception:
        pass
    await _kill(sess.container)
    return {"stopped": session_id}


async def _kill(container) -> None:
    loop = asyncio.get_running_loop()
    try:
        await loop.run_in_executor(None, lambda: container.remove(force=True))
    except Exception as e:
        logger.warning("ghidra container cleanup error: %s", e)


async def reconcile_orphan_ghidra_sessions() -> int:
    """Remove ghidra_session containers left by a prior server process."""
    try:
        client = _client()
        loop = asyncio.get_running_loop()
        orphans = await loop.run_in_executor(None, lambda: client.containers.list(
            all=True, filters={"label": "ctftoolkit.tool=ghidra_session"}))
        n = 0
        for c in orphans:
            if c.labels.get("ctftoolkit.session_id") in _sessions:
                continue
            try:
                await loop.run_in_executor(None, lambda c=c: c.remove(force=True))
                n += 1
            except Exception as e:
                logger.warning("could not remove orphan ghidra container %s: %s", c.name, e)
        if n:
            logger.info("reconciled %d orphan ghidra session container(s)", n)
        return n
    except Exception as e:
        logger.warning("ghidra orphan reconciliation skipped: %s", e)
        return 0
