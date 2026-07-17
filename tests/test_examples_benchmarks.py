from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ctf_core.artifact_triage import triage_artifact
from ctf_core.workflows import suggest_next_tools


REPO_ROOT = Path(__file__).resolve().parents[1]
EXAMPLES_ROOT = REPO_ROOT / "examples" / "local_challenges"
GOLDEN_ROOT = REPO_ROOT / "tests" / "golden"
REQUIRED_CATEGORIES = {"web", "re", "crypto", "pwn", "forensics"}
MAX_FIXTURE_BYTES = 16 * 1024
EXECUTABLE_MAGICS = (b"\x7fELF", b"MZ")
DANGEROUS_MARKERS = (
    b"-----begin private key-----",
    b"/bin/sh",
    b"cmd.exe",
    b"powershell -enc",
    b"meterpreter",
    b"reverse shell",
)


def _load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _repo_path(relative_path: str) -> Path:
    path = (REPO_ROOT / relative_path).resolve()
    assert path.is_relative_to(REPO_ROOT)
    return path


def _tool_names(recommendations: list[dict[str, Any]]) -> list[str]:
    return [str(item["tool"]) for item in recommendations]


def _challenge_metadata() -> dict[str, tuple[Path, dict[str, Any]]]:
    challenges: dict[str, tuple[Path, dict[str, Any]]] = {}
    for path in sorted(EXAMPLES_ROOT.glob("*/challenge.json")):
        data = _load_json(path)
        challenges[str(data["id"])] = (path, data)
    return challenges


def _assert_tool_expectations(
    tools: list[str],
    *,
    prefix: list[str],
    includes: list[str],
) -> None:
    assert tools[: len(prefix)] == prefix
    for tool in includes:
        assert tool in tools


def test_local_example_challenges_are_safe_and_cover_required_categories() -> None:
    challenges = _challenge_metadata()
    categories = {str(data["category"]) for _, data in challenges.values()}

    assert REQUIRED_CATEGORIES <= categories
    assert set(challenges) == {
        "crypto-toy-rsa",
        "forensics-packet-note",
        "pwn-stack-note",
        "re-wasm-checker",
        "web-hidden-login",
    }

    for challenge_path, data in challenges.values():
        assert data["safe_fixture"] is True
        challenge_root = challenge_path.parent.resolve()

        for artifact in data["artifacts"]:
            artifact_path = (challenge_path.parent / str(artifact)).resolve()
            assert artifact_path.is_relative_to(challenge_root)
            assert artifact_path.is_file()

            contents = artifact_path.read_bytes()
            assert 0 < len(contents) <= MAX_FIXTURE_BYTES
            assert not contents.startswith(EXECUTABLE_MAGICS)

            lowered = contents.lower()
            for marker in DANGEROUS_MARKERS:
                assert marker not in lowered


def test_artifact_triage_matches_golden_outputs() -> None:
    golden = _load_json(GOLDEN_ROOT / "artifact_triage_expectations.json")

    for item in golden["artifacts"]:
        result = triage_artifact(_repo_path(item["path"]))
        expected = item["expected"]
        tools = _tool_names(result["recommended_next_tools"])

        assert result["sha256"] == expected["sha256"]
        assert result["size"] == expected["size"]
        assert result["suffix"] == expected["suffix"]
        assert result["category_hint"] == expected["category_hint"]
        assert set(expected["type_hints"]) <= set(result["type_hints"])
        assert set(expected["string_samples"]) <= set(result["string_samples"])
        _assert_tool_expectations(
            tools,
            prefix=expected["recommended_tools_prefix"],
            includes=expected["recommended_tools_include"],
        )


def test_workflow_suggestions_match_golden_outputs() -> None:
    golden = _load_json(GOLDEN_ROOT / "workflow_suggestion_expectations.json")

    for item in golden["cases"]:
        recommendations = suggest_next_tools(**item["input"])
        tools = _tool_names(recommendations)
        by_tool = {str(rec["tool"]): rec for rec in recommendations}

        _assert_tool_expectations(
            tools,
            prefix=item["expected_tools_prefix"],
            includes=item["expected_tools_include"],
        )
        for tool, category in item["expected_categories"].items():
            assert by_tool[tool]["category"] == category


def test_benchmark_definitions_measure_all_local_examples() -> None:
    suite = _load_json(EXAMPLES_ROOT / "benchmarks.json")
    golden = _load_json(GOLDEN_ROOT / "benchmark_expectations.json")
    expectations = golden["expectations"]
    challenges = _challenge_metadata()

    benchmark_ids = {str(item["id"]) for item in suite["benchmarks"]}
    assert benchmark_ids == set(expectations)

    measured_categories: set[str] = set()
    results: list[dict[str, Any]] = []

    for benchmark in suite["benchmarks"]:
        benchmark_id = str(benchmark["id"])
        expectation = expectations[benchmark_id]
        challenge_path = _repo_path(benchmark["challenge_path"])
        artifact_path = _repo_path(benchmark["artifact_path"])
        _, challenge = challenges[str(benchmark["challenge_id"])]

        assert challenge_path.is_file()
        assert artifact_path.is_file()
        assert benchmark["measurements"] == ["triage_artifact", "suggest_next_tools"]
        assert challenge["category"] == expectation["expected_challenge_category"]

        triage = triage_artifact(artifact_path)
        recommendations = suggest_next_tools(**benchmark["suggestion_input"])
        triage_tools = set(_tool_names(triage["recommended_next_tools"]))
        suggested_tools = set(_tool_names(recommendations))

        suggested_hits = suggested_tools & set(expectation["suggested_tools_include"])
        triage_hits = triage_tools & set(expectation["triage_tools_include"])
        measured_categories.add(str(challenge["category"]))
        results.append(
            {
                "id": benchmark_id,
                "suggested_hits": len(suggested_hits),
                "triage_hits": len(triage_hits),
            }
        )

        assert triage["category_hint"] == expectation["expected_triage_category"]
        assert len(suggested_hits) >= expectation["minimum_suggested_hits"]
        assert len(triage_hits) >= expectation["minimum_triage_hits"]

    assert measured_categories == REQUIRED_CATEGORIES
    assert all(result["suggested_hits"] > 0 for result in results)
    assert all(result["triage_hits"] > 0 for result in results)
