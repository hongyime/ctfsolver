"""Build all CTF Toolkit Docker images.

Cross-platform image builder that surfaces real Docker errors (unlike the
legacy setup.bat / setup.sh which silently swallowed stderr with `2>nul`).

Usage:
    python scripts/build_images.py                  # build all 5 core images
    python scripts/build_images.py ctf-tools        # build a single image
    python scripts/build_images.py --no-cache       # rebuild from scratch
    python scripts/build_images.py --check          # only verify, do not build

The script uses the docker SDK (already a dependency) and walks the
`docker/` subdirectory next to the project root.
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path
from typing import Iterable

# Build output from Kali/Debian apt can contain non-cp1252 Unicode (e.g. U+2192 '→').
# The default Windows console encoding (cp1252) raises UnicodeEncodeError mid-build and
# aborts the build. Force UTF-8 with error replacement so streaming logs never crash.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
    except (AttributeError, ValueError):
        pass

import docker  # noqa: E402
from docker.errors import APIError, BuildError, DockerException  # noqa: E402


PROJECT_ROOT = Path(__file__).resolve().parent.parent
DOCKER_DIR = PROJECT_ROOT / "docker"

# Image set must stay in sync with docker_runner.TOOL_IMAGES values.
# Each entry: (image_tag, dockerfile_path_relative_to_root)
IMAGES: list[tuple[str, str]] = [
    ("ctftoolkit/ctf-tools", "docker/ctf-tools/Dockerfile"),
    ("ctftoolkit/ctf-pwn", "docker/ctf-pwn/Dockerfile"),
    ("ctftoolkit/ctf-forensics", "docker/ctf-forensics/Dockerfile"),
    ("ctftoolkit/ctf-re", "docker/ctf-re/Dockerfile"),
    ("ctftoolkit/ctf-crypto", "docker/ctf-crypto/Dockerfile"),
]

# Heavy, lazy-built-only images (UPGRADE_PLAN.md §6). Excluded from the default
# build-all so a fresh clone is not forced to build ~2.5GB of SageMath. Built only
# when named explicitly (e.g. `python scripts/build_images.py ctf-sage ctf-mobile`)
# or lazily on first matching tool use.
LAZY_IMAGES: list[tuple[str, str]] = [
    ("ctftoolkit/ctf-mobile", "docker/ctf-mobile/Dockerfile"),
    ("ctftoolkit/ctf-sage", "docker/ctf-sage/Dockerfile"),
]
LAZY_IMAGE_TAGS = {tag for tag, _ in LAZY_IMAGES}

# All known images (core + lazy) for selection/--check.
ALL_IMAGES: list[tuple[str, str]] = IMAGES + LAZY_IMAGES


def _color(text: str, code: str) -> str:
    if not sys.stdout.isatty():
        return text
    return f"\033[{code}m{text}\033[0m"


def green(text: str) -> str:
    return _color(text, "32")


def red(text: str) -> str:
    return _color(text, "31")


def yellow(text: str) -> str:
    return _color(text, "33")


def cyan(text: str) -> str:
    return _color(text, "36")


def get_client() -> docker.DockerClient:
    try:
        client = docker.from_env()
        client.ping()
        return client
    except DockerException as exc:
        print(red(f"ERROR: Docker daemon not reachable: {exc}"))
        print("       Make sure Docker Desktop / dockerd is running, then retry.")
        sys.exit(2)


def image_exists(client: docker.DockerClient, tag: str) -> bool:
    try:
        client.images.get(tag)
        return True
    except docker.errors.ImageNotFound:
        return False


def build_one(
    client: docker.DockerClient,
    tag: str,
    dockerfile_rel: str,
    *,
    no_cache: bool = False,
) -> bool:
    dockerfile = PROJECT_ROOT / dockerfile_rel
    if not dockerfile.is_file():
        print(red(f"  [MISSING] Dockerfile not found at {dockerfile}"))
        return False

    print(cyan(f"  Building {tag}"))
    print(f"  Context:    {PROJECT_ROOT}")
    print(f"  Dockerfile: {dockerfile_rel}")
    if no_cache:
        print(f"  Cache:      {yellow('DISABLED (--no-cache)')}")
    print()

    started = time.monotonic()
    try:
        # low-level API gives a streaming JSON log we can render incrementally
        api = client.api
        stream = api.build(
            path=str(PROJECT_ROOT),
            dockerfile=dockerfile_rel.replace("\\", "/"),
            tag=tag,
            rm=True,
            forcerm=True,
            nocache=no_cache,
            decode=True,
        )
        last_status: str | None = None
        for chunk in stream:
            if "stream" in chunk:
                line = chunk["stream"].rstrip()
                if line:
                    print(f"    {line}")
            elif "status" in chunk:
                status = chunk["status"]
                if status != last_status:
                    print(f"    [{status}]")
                    last_status = status
            elif "error" in chunk:
                err = chunk["error"]
                print(red(f"    BUILD ERROR: {err}"))
                return False
        elapsed = time.monotonic() - started
        print(green(f"  [OK] {tag} built in {elapsed:.1f}s"))
        return True

    except BuildError as exc:
        print(red(f"  [X] Build failed: {exc.msg}"))
        for entry in exc.build_log:
            if "stream" in entry:
                print(f"    {entry['stream'].rstrip()}")
        return False
    except APIError as exc:
        print(red(f"  [X] Docker API error: {exc.explanation or exc}"))
        return False


def select(images: list[tuple[str, str]], names: Iterable[str]) -> list[tuple[str, str]]:
    if not names:
        return images
    wanted = {n.strip().rstrip("/") for n in names}
    # accept either "ctf-tools" or "ctftoolkit/ctf-tools"
    selected: list[tuple[str, str]] = []
    for tag, df in images:
        short = tag.split("/", 1)[-1]
        if tag in wanted or short in wanted:
            selected.append((tag, df))
    missing = wanted - {tag for tag, _ in selected} - {tag.split("/", 1)[-1] for tag, _ in selected}
    if missing:
        print(red(f"Unknown image(s): {', '.join(sorted(missing))}"))
        print(f"Available: {', '.join(short for _, short in ((t, t.split('/',1)[-1]) for t,_ in images))}")
        sys.exit(1)
    return selected


def main() -> int:
    parser = argparse.ArgumentParser(description="Build CTF Toolkit Docker images")
    parser.add_argument("names", nargs="*", help="image short names (e.g. ctf-tools); default = all")
    parser.add_argument("--no-cache", action="store_true", help="force fresh build")
    parser.add_argument("--check", action="store_true", help="only report which images exist")
    parser.add_argument("--skip-existing", action="store_true", help="skip images already built")
    args = parser.parse_args()

    client = get_client()
    # Selection: explicit names may target any known image (including lazy
    # ctf-sage/ctf-mobile); default build-all uses core IMAGES only.
    if args.names:
        targets = select(ALL_IMAGES, args.names)
    elif args.check:
        targets = ALL_IMAGES
    else:
        targets = IMAGES

    print(cyan("CTF Toolkit — Docker image builder"))
    print(f"Project root: {PROJECT_ROOT}")
    print(f"Targets:      {len(targets)} image(s)")
    print()

    if args.check:
        any_missing = False
        explicit_check = bool(args.names)
        for tag, _ in targets:
            present = image_exists(client, tag)
            lazy = tag in LAZY_IMAGE_TAGS
            if present:
                mark = green("[OK]")
                label = "present"
            elif lazy and not explicit_check:
                mark = yellow("[~] ")
                label = "MISSING (lazy; build explicitly when needed)"
            else:
                mark = red("[X] ")
                label = "MISSING"
            print(f"  {mark} {tag:<32} {label}")
            if not present and (explicit_check or not lazy):
                any_missing = True
        return 1 if any_missing else 0

    results: dict[str, bool] = {}
    for tag, dockerfile in targets:
        if args.skip_existing and image_exists(client, tag):
            print(green(f"[SKIP] {tag} already built"))
            results[tag] = True
            continue
        print(cyan(f"--- {tag} ---"))
        ok = build_one(client, tag, dockerfile, no_cache=args.no_cache)
        results[tag] = ok
        print()

    print(cyan("Summary"))
    print("=" * 40)
    failed = [t for t, ok in results.items() if not ok]
    for tag, ok in results.items():
        mark = green("[OK]") if ok else red("[X] ")
        print(f"  {mark} {tag}")
    print()
    if failed:
        print(red(f"{len(failed)} image(s) failed to build."))
        print("Re-run with the failing image name to retry, e.g.:")
        print(f"  python scripts/build_images.py {failed[0].split('/',1)[-1]}")
        return 1

    print(green(f"All {len(results)} images built successfully."))
    print("You can now run any CTF Toolkit MCP tool. Containers are ephemeral —")
    print("they will not appear in `docker ps -a` unless a scan is in progress.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
