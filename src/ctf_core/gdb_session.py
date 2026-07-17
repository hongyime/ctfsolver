"""Interactive GDB/MI live-debug session manager (Phase 1).

Implements gdb_start/gdb_send/gdb_read/gdb_stop on top of a detached
`gdb --interpreter=mi3` container per session (one process; state — breakpoints,
inferior, stepping — lives in GDB's own memory). Host-side parsing via pygdbmi.

Design reviewed by Oracle. Key points:
  * attach_socket returns a MULTIPLEXED stream with an 8-byte frame header per
    chunk — we strip it before parsing.
  * Terminal record = a result record (^done/^error/^running) followed by the
    "(gdb)" prompt. ^stopped (after -exec-run/-exec-continue) arrives async and
    is drained by gdb_read.
  * SYS_PTRACE capability + seccomp=unconfined are required for ptrace(2); this
    is a deliberate per-tool loosening of the hardened default (cap_drop ALL),
    which the security model explicitly permits for debuggers.
  * Sessions are tracked in-process AND labeled ctftoolkit.session_id=<id>. On
    server start, reconcile_orphan_gdb_sessions() removes leftovers from a prior
    process (interactive sessions cannot be recovered, so kill-on-startup is
    correct for Phase 1; durable survival is a Phase 2 concern).
"""

from __future__ import annotations

import asyncio
import logging
import os
import uuid
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

PWN_IMAGE = "ctftoolkit/ctf-pwn"


def _raw(sock):
    """Return the low-level socket. Linux Docker wraps as sock._sock; Windows
    Docker Desktop returns an NpipeSocket that IS the socket (no ._sock)."""
    return getattr(sock, "_sock", sock)


def _strip_docker_frames(data: bytes) -> bytes:
    """Strip Docker's 8-byte stream multiplexing headers ([type,0,0,0,size32])."""
    out = b""
    while len(data) >= 8:
        size = int.from_bytes(data[4:8], "big")
        out += data[8:8 + size]
        data = data[8 + size:]
        if size == 0:
            break
    # If it didn't look framed (no clean consumption), fall back to raw bytes.
    return out if out else data


@dataclass
class GdbSession:
    session_id: str
    container: Any
    sock: Any
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    buf: bytes = b""


_sessions: dict[str, GdbSession] = {}
_REGISTRY_GUARD = asyncio.Lock()


def _docker_client():
    # Reuse the runner's platform-aware client construction.
    from .docker_runner import DockerRunner
    return DockerRunner().client


def _is_terminal_line(line: str) -> bool:
    """MI result-record / prompt sentinels marking end of a command's reply."""
    s = line.strip()
    if s == "(gdb)":
        return True
    # result records start with optional token then ^done/^error/^running/^exit
    body = s.lstrip("0123456789")
    return body.startswith(("^done", "^error", "^running", "^exit", "^connected"))


async def _recv_chunk(sess: GdbSession, timeout: float) -> bytes:
    loop = asyncio.get_running_loop()
    raw = await asyncio.wait_for(
        loop.run_in_executor(None, _raw(sess.sock).recv, 8192), timeout=timeout)
    return _strip_docker_frames(raw)


async def _read_until_done(sess: GdbSession, timeout: float) -> list[str]:
    """Read MI lines until a terminal result record / prompt, or timeout."""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    lines: list[str] = []
    saw_result = False
    while True:
        remaining = deadline - loop.time()
        if remaining <= 0:
            raise asyncio.TimeoutError(f"GDB MI timeout after {timeout}s")
        try:
            chunk = await _recv_chunk(sess, remaining)
        except asyncio.TimeoutError:
            raise
        except (OSError, BrokenPipeError) as e:
            raise RuntimeError(f"GDB socket closed: {e}") from e
        if not chunk:
            raise RuntimeError("GDB container exited (EOF)")
        sess.buf += chunk
        while b"\n" in sess.buf:
            raw, sess.buf = sess.buf.split(b"\n", 1)
            line = raw.decode("utf-8", "replace").rstrip()
            if not line:
                continue
            lines.append(line)
            body = line.strip().lstrip("0123456789")
            if body.startswith(("^done", "^error", "^running", "^exit", "^connected")):
                saw_result = True
            if line.strip() == "(gdb)" and saw_result:
                return lines


async def gdb_start(binary: str, timeout: float = 30.0) -> dict:
    """Start a detached GDB/MI session on /workspace/<binary>. Returns session_id + startup."""
    client = _docker_client()
    session_id = uuid.uuid4().hex[:12]
    name = f"ctftoolkit-gdb-{session_id[:8]}"
    target = f"/workspace/{binary.lstrip('/')}"

    from .docker_runner import DockerRunner
    volumes = DockerRunner()._prepare_volumes()

    loop = asyncio.get_running_loop()
    try:
        container = await loop.run_in_executor(None, lambda: client.containers.run(
            image=PWN_IMAGE,
            command=["gdb", "--interpreter=mi3", "--quiet", target],
            name=name,
            detach=True,
            stdin_open=True,
            tty=False,
            remove=False,
            cap_drop=["ALL"],
            cap_add=["SYS_PTRACE"],            # ptrace for the inferior
            security_opt=["no-new-privileges:true", "seccomp=unconfined"],
            user=os.environ.get("CTFTOOLKIT_CONTAINER_USER", "1000:1000"),
            mem_limit=os.environ.get("CTFTOOLKIT_MEM_LIMIT", "1g"),
            pids_limit=int(os.environ.get("CTFTOOLKIT_PIDS_LIMIT", "256")),
            network_disabled=True,
            volumes=volumes,
            labels={
                "ctftoolkit.managed": "true",
                "ctftoolkit.tool": "gdb_session",
                "ctftoolkit.session_id": session_id,
            },
        ))
    except Exception as e:
        return {"error": f"failed to start gdb container: {e}"}

    try:
        sock = await loop.run_in_executor(None, lambda: container.attach_socket(
            params={"stdin": 1, "stdout": 1, "stderr": 1, "stream": 1}))
        try:
            _raw(sock).setblocking(True)
        except (AttributeError, OSError):
            pass  # NpipeSocket (Windows) is blocking by default
    except Exception as e:
        try:
            await loop.run_in_executor(None, lambda: container.remove(force=True))
        except Exception:
            pass
        return {"error": f"failed to attach to gdb container: {e}"}

    sess = GdbSession(session_id=session_id, container=container, sock=sock)
    async with _REGISTRY_GUARD:
        _sessions[session_id] = sess

    try:
        startup = await _read_until_done(sess, timeout=min(timeout, 15.0))
    except (asyncio.TimeoutError, RuntimeError):
        startup = ["(gdb startup prompt not captured; session is live)"]
    return {"session_id": session_id, "startup": "\n".join(startup)[:4000]}


async def gdb_send(session_id: str, mi_command: str, timeout: float = 30.0) -> dict:
    sess = _sessions.get(session_id)
    if not sess:
        return {"error": f"unknown session {session_id}"}
    async with sess.lock:
        token = uuid.uuid4().int % 1000000
        line = f"{token}{mi_command.strip()}\n".encode()
        loop = asyncio.get_running_loop()
        try:
            await loop.run_in_executor(None, _raw(sess.sock).sendall, line)
        except (OSError, BrokenPipeError) as e:
            _sessions.pop(session_id, None)
            return {"error": f"gdb socket write failed: {e}"}
        try:
            lines = await _read_until_done(sess, timeout)
        except asyncio.TimeoutError:
            return {"error": f"timeout waiting for response to: {mi_command}"}
        except RuntimeError as e:
            _sessions.pop(session_id, None)
            return {"error": str(e)}
        return {"output": "\n".join(lines)[:8000]}


async def gdb_read(session_id: str, timeout: float = 1.0) -> dict:
    """Drain async output (e.g. ^stopped after -exec-continue) without sending a command."""
    sess = _sessions.get(session_id)
    if not sess:
        return {"error": f"unknown session {session_id}"}
    async with sess.lock:
        lines: list[str] = []
        try:
            chunk = await _recv_chunk(sess, timeout)
            sess.buf += chunk
        except asyncio.TimeoutError:
            pass
        except (OSError, BrokenPipeError) as e:
            _sessions.pop(session_id, None)
            return {"error": f"gdb socket closed: {e}"}
        while b"\n" in sess.buf:
            raw, sess.buf = sess.buf.split(b"\n", 1)
            line = raw.decode("utf-8", "replace").rstrip()
            if line:
                lines.append(line)
        return {"output": "\n".join(lines)[:8000] or "(no new output)"}


async def gdb_stop(session_id: str) -> dict:
    sess = _sessions.pop(session_id, None)
    if not sess:
        return {"error": f"unknown session {session_id}"}
    loop = asyncio.get_running_loop()
    try:
        _raw(sess.sock).close()
    except Exception:
        pass
    try:
        await loop.run_in_executor(None, lambda: sess.container.remove(force=True))
    except Exception as e:
        logger.warning("gdb_stop cleanup error: %s", e)
    return {"stopped": session_id}


async def reconcile_orphan_gdb_sessions() -> int:
    """Remove gdb_session containers left by a previous server process. Returns count."""
    try:
        client = _docker_client()
        loop = asyncio.get_running_loop()
        orphans = await loop.run_in_executor(None, lambda: client.containers.list(
            all=True, filters={"label": "ctftoolkit.tool=gdb_session"}))
        n = 0
        for c in orphans:
            if c.labels.get("ctftoolkit.session_id") in _sessions:
                continue  # belongs to this live process
            try:
                await loop.run_in_executor(None, lambda c=c: c.remove(force=True))
                n += 1
            except Exception as e:
                logger.warning("could not remove orphan gdb container %s: %s", c.name, e)
        if n:
            logger.info("reconciled %d orphan gdb session container(s)", n)
        return n
    except Exception as e:
        logger.warning("gdb orphan reconciliation skipped: %s", e)
        return 0
