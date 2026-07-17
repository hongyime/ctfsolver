"""Dry-run-first update planner for CTF Toolkit images and local metadata."""

from __future__ import annotations

import argparse
import subprocess
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable, Iterable, Sequence


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from ctf_core.docker_status import discover_image_definitions  # noqa: E402


DEFAULT_COMPONENTS = ("images", "nuclei-templates", "exploit-db", "wordlists", "local-metadata")
VALID_COMPONENTS = frozenset(DEFAULT_COMPONENTS)
CTF_TOOLS_SERVICE = "ctf-tools"
CTF_TOOLS_IMAGE = "ctftoolkit/ctf-tools"


@dataclass(frozen=True, slots=True)
class UpdateStep:
    component: str
    description: str
    command: tuple[str, ...]
    network: bool = True
    conservative_note: str = ""

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class UpdatePlan:
    dry_run: bool
    steps: tuple[UpdateStep, ...]
    warnings: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


Executor = Callable[[Sequence[str]], subprocess.CompletedProcess[str]]


def _python_command(*args: str) -> tuple[str, ...]:
    return (sys.executable, *args)


def _command_text(command: Sequence[str]) -> str:
    return subprocess.list2cmdline([str(part) for part in command])


def _selected_components(components: Iterable[str] | None) -> tuple[str, ...]:
    selected = tuple(components or DEFAULT_COMPONENTS)
    unknown = sorted(set(selected) - VALID_COMPONENTS)
    if unknown:
        raise ValueError(f"unknown update component(s): {', '.join(unknown)}")
    return selected


def _image_steps(
    *,
    image_names: Iterable[str] | None,
    include_lazy: bool,
    project_root: Path,
) -> tuple[UpdateStep, ...]:
    wanted = {name.strip() for name in (image_names or ()) if name.strip()}
    definitions = discover_image_definitions(project_root)
    steps: list[UpdateStep] = []
    matched: set[str] = set()
    for definition in definitions:
        short = definition.image.split("/", 1)[-1]
        if definition.lazy and not include_lazy and not wanted:
            continue
        if wanted and definition.image not in wanted and short not in wanted and (definition.service or "") not in wanted:
            continue
        matched.update({definition.image, short})
        service = definition.service or short
        steps.append(
            UpdateStep(
                component="images",
                description=f"Rebuild {definition.image} with latest base/package data",
                command=("docker", "compose", "build", "--pull", service),
                conservative_note="Builds one named service; does not prune or remove existing images.",
            )
        )
    missing = wanted - matched
    if missing:
        raise ValueError(f"unknown image target(s): {', '.join(sorted(missing))}")
    return tuple(steps)


def build_update_plan(
    *,
    components: Iterable[str] | None = None,
    image_names: Iterable[str] | None = None,
    include_lazy: bool = False,
    dry_run: bool = True,
    project_root: Path | None = None,
) -> UpdatePlan:
    """Build a conservative update plan. No command is executed here."""

    root = (project_root or PROJECT_ROOT).resolve()
    selected = _selected_components(components)
    steps: list[UpdateStep] = []
    warnings: list[str] = []

    if "images" in selected:
        steps.extend(_image_steps(image_names=image_names, include_lazy=include_lazy, project_root=root))
        if not include_lazy:
            warnings.append("lazy image ctftoolkit/ctf-sage is skipped unless --include-lazy or --image ctf-sage is used")

    if "nuclei-templates" in selected:
        steps.append(
            UpdateStep(
                component="nuclei-templates",
                description="Refresh nuclei templates baked into the ctf-tools image",
                command=("docker", "compose", "build", "--pull", CTF_TOOLS_SERVICE),
                conservative_note="Templates are cloned during the image build, so rebuilding ctf-tools preserves the update.",
            )
        )

    if "exploit-db" in selected:
        steps.append(
            UpdateStep(
                component="exploit-db",
                description="Refresh exploit-db/searchsploit data through the ctf-tools image",
                command=("docker", "compose", "build", "--pull", CTF_TOOLS_SERVICE),
                conservative_note="Uses the Dockerfile/package build path rather than mutating a running container.",
            )
        )

    if "wordlists" in selected:
        steps.append(
            UpdateStep(
                component="wordlists",
                description="Refresh packaged wordlist data through the ctf-tools image",
                command=("docker", "compose", "build", "--pull", CTF_TOOLS_SERVICE),
                conservative_note="Does not download arbitrary wordlists outside the Docker build context.",
            )
        )

    if "local-metadata" in selected:
        steps.append(
            UpdateStep(
                component="local-metadata",
                description="Regenerate local toolkit manifest metadata",
                command=_python_command("scripts/generate_manifest.py", "--write"),
                network=False,
                conservative_note="Updates only the deterministic local manifest.",
            )
        )

    return UpdatePlan(dry_run=dry_run, steps=tuple(steps), warnings=tuple(warnings))


def _default_executor(command: Sequence[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        list(command),
        capture_output=True,
        text=True,
        check=False,
        cwd=PROJECT_ROOT,
    )


def run_plan(
    plan: UpdatePlan,
    *,
    executor: Executor | None = None,
    out: object | None = None,
) -> int:
    """Print and optionally execute a plan. Dry-run mode never calls executor."""

    stream = out if out is not None else sys.stdout
    print("CTF Toolkit update plan", file=stream)
    print(f"Mode: {'dry-run' if plan.dry_run else 'apply'}", file=stream)
    for warning in plan.warnings:
        print(f"Warning: {warning}", file=stream)
    print("", file=stream)

    if not plan.steps:
        print("No update steps selected.", file=stream)
        return 0

    for index, step in enumerate(plan.steps, start=1):
        print(f"{index}. [{step.component}] {step.description}", file=stream)
        print(f"   command: {_command_text(step.command)}", file=stream)
        if step.conservative_note:
            print(f"   note: {step.conservative_note}", file=stream)
        if plan.dry_run:
            continue

        runner = executor or _default_executor
        completed = runner(step.command)
        if completed.stdout:
            print(completed.stdout.rstrip(), file=stream)
        if completed.stderr:
            print(completed.stderr.rstrip(), file=stream)
        if completed.returncode != 0:
            print(f"Step failed with exit code {completed.returncode}", file=stream)
            return completed.returncode

    if plan.dry_run:
        print("", file=stream)
        print("Dry run only. Re-run with --apply to execute these commands.", file=stream)
    return 0


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Plan or apply CTF Toolkit tool updates.")
    parser.add_argument(
        "--apply",
        action="store_true",
        help="execute the printed commands; default is dry-run",
    )
    parser.add_argument(
        "--component",
        action="append",
        choices=sorted(VALID_COMPONENTS),
        help="update only this component; may be repeated",
    )
    parser.add_argument(
        "--image",
        action="append",
        default=[],
        help="limit image rebuilds to an image/service name such as ctf-tools or ctftoolkit/ctf-tools",
    )
    parser.add_argument(
        "--include-lazy",
        action="store_true",
        help="include lazy heavy images such as ctf-sage in default image updates",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        plan = build_update_plan(
            components=args.component,
            image_names=args.image,
            include_lazy=args.include_lazy,
            dry_run=not args.apply,
        )
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    return run_plan(plan)


if __name__ == "__main__":
    raise SystemExit(main())
