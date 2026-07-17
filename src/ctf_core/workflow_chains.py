"""Declarative workflow chain metadata for common CTF paths.

This module is intentionally data-only. It ranks and returns ordered workflow
chains, but it never imports the MCP server, starts Docker, opens files, or
touches the network.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import PurePath
import re
from typing import Any


ParameterTemplates = tuple[tuple[str, str], ...]


@dataclass(frozen=True)
class WorkflowStep:
    """One planned step in a chain.

    ``parameter_templates`` are placeholders for a future orchestrator. They
    are not executable command lines.
    """

    step_id: str
    tool: str
    purpose: str
    parameter_templates: ParameterTemplates
    prerequisites: tuple[str, ...]
    safety_notes: tuple[str, ...]
    expected_artifacts: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "step_id": self.step_id,
            "tool": self.tool,
            "purpose": self.purpose,
            "parameter_templates": dict(self.parameter_templates),
            "prerequisites": list(self.prerequisites),
            "safety_notes": list(self.safety_notes),
            "expected_artifacts": list(self.expected_artifacts),
        }


@dataclass(frozen=True)
class WorkflowChain:
    """An ordered, declarative workflow chain."""

    chain_id: str
    name: str
    category: str
    description: str
    selection_categories: tuple[str, ...]
    trigger_keywords: tuple[str, ...]
    file_suffixes: tuple[str, ...]
    target_hints: tuple[str, ...]
    prerequisites: tuple[str, ...]
    safety_notes: tuple[str, ...]
    steps: tuple[WorkflowStep, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "chain_id": self.chain_id,
            "name": self.name,
            "category": self.category,
            "description": self.description,
            "selection_categories": list(self.selection_categories),
            "trigger_keywords": list(self.trigger_keywords),
            "file_suffixes": list(self.file_suffixes),
            "target_hints": list(self.target_hints),
            "prerequisites": list(self.prerequisites),
            "safety_notes": list(self.safety_notes),
            "steps": [step.to_dict() for step in self.steps],
        }


def _params(*items: tuple[str, str]) -> ParameterTemplates:
    return tuple(items)


def _tuple(value: tuple[str, ...] | str) -> tuple[str, ...]:
    if isinstance(value, str):
        return (value,)
    return tuple(value)


def _step(
    step_id: str,
    tool: str,
    purpose: str,
    parameter_templates: ParameterTemplates,
    prerequisites: tuple[str, ...] | str,
    safety_notes: tuple[str, ...] | str,
    expected_artifacts: tuple[str, ...] | str = (),
) -> WorkflowStep:
    return WorkflowStep(
        step_id=step_id,
        tool=tool,
        purpose=purpose,
        parameter_templates=parameter_templates,
        prerequisites=_tuple(prerequisites),
        safety_notes=_tuple(safety_notes),
        expected_artifacts=_tuple(expected_artifacts),
    )


_SCOPE_PREREQ = "Authorized target scope is configured for the target."
_SCOPE_SAFETY = "Run only against in-scope targets and preserve rate limits."
_LOCAL_FILE_PREREQ = "Challenge artifact is available in the workspace."
_LOCAL_FILE_SAFETY = "Treat artifacts as untrusted and keep extraction inside the workspace."


WORKFLOW_CHAINS: tuple[WorkflowChain, ...] = (
    WorkflowChain(
        chain_id="web_recon",
        name="Web Recon",
        category="web",
        description=(
            "Fingerprint the target, discover directories and parameters, run a "
            "low-impact nuclei pass, then summarize findings."
        ),
        selection_categories=("web", "recon"),
        trigger_keywords=(
            "web",
            "http",
            "https",
            "recon",
            "fingerprint",
            "directory",
            "directories",
            "endpoint",
            "parameter",
            "params",
            "nuclei",
            "admin",
        ),
        file_suffixes=(".html", ".js", ".json", ".har"),
        target_hints=("url", "host"),
        prerequisites=(
            _SCOPE_PREREQ,
            "A base URL or host is known.",
            "Challenge rules allow light web enumeration.",
        ),
        safety_notes=(
            _SCOPE_SAFETY,
            "Start with passive or low-concurrency checks before fuzzing.",
        ),
        steps=(
            _step(
                "fingerprint",
                "whatweb",
                "Identify server, framework, headers, and obvious technologies.",
                _params(
                    ("target", "{target}"),
                    ("aggression", "{aggression:1}"),
                    ("output", "{workspace}/web/whatweb.json"),
                ),
                (_SCOPE_PREREQ, "Base URL responds or is expected to respond."),
                (_SCOPE_SAFETY, "Keep fingerprinting to a single base target first."),
                ("technology_fingerprint", "headers"),
            ),
            _step(
                "probe-live",
                "httpx",
                "Normalize reachable URLs and capture status, title, and tech hints.",
                _params(
                    ("input", "{target_or_url_list}"),
                    ("threads", "{threads:10}"),
                    ("timeout", "{timeout_seconds:5}"),
                    ("output", "{workspace}/web/httpx.jsonl"),
                ),
                (_SCOPE_PREREQ, "Targets are in the saved scope."),
                (_SCOPE_SAFETY, "Use bounded concurrency and timeout settings."),
                ("live_url_list",),
            ),
            _step(
                "discover-directories",
                "feroxbuster",
                "Enumerate content paths with conservative depth and status filters.",
                _params(
                    ("url", "{base_url}"),
                    ("wordlist", "{wordlist:common_web}"),
                    ("threads", "{threads:10}"),
                    ("depth", "{depth:1}"),
                    ("output", "{workspace}/web/feroxbuster.json"),
                ),
                (_SCOPE_PREREQ, "Base URL and wordlist are selected."),
                (_SCOPE_SAFETY, "Avoid recursive or high-rate brute force by default."),
                ("discovered_paths",),
            ),
            _step(
                "discover-parameters",
                "ffuf",
                "Probe known endpoints for common query and form parameters.",
                _params(
                    ("url_template", "{base_url}/{path}?FUZZ=test"),
                    ("wordlist", "{wordlist:parameters_small}"),
                    ("match_codes", "{match_codes:200,204,301,302,307,401,403}"),
                    ("output", "{workspace}/web/ffuf-params.json"),
                ),
                (_SCOPE_PREREQ, "Candidate paths exist from crawl or directory discovery."),
                (_SCOPE_SAFETY, "Use a small parameter list before broader fuzzing."),
                ("candidate_parameters",),
            ),
            _step(
                "nuclei-lite",
                "nuclei",
                "Run severity-filtered, rate-limited templates for common misconfigurations.",
                _params(
                    ("target", "{base_url}"),
                    ("severity", "{severity:low,medium,high,critical}"),
                    ("tags", "{tags:exposure,misconfig,cves}"),
                    ("rate_limit", "{rate_limit:5}"),
                    ("output", "{workspace}/web/nuclei-lite.jsonl"),
                ),
                (_SCOPE_PREREQ, "Template policy is selected."),
                (
                    _SCOPE_SAFETY,
                    "Prefer signed or locally reviewed templates for autonomous runs.",
                ),
                ("nuclei_findings",),
            ),
            _step(
                "summary",
                "manual-review",
                "Merge fingerprints, endpoints, parameters, and findings into next actions.",
                _params(
                    ("inputs", "{workspace}/web/*.json*"),
                    ("output", "{workspace}/web/recon-summary.md"),
                ),
                ("Recon outputs exist.",),
                ("Do not treat scanner output as proof without reproduction.",),
                ("recon_summary",),
            ),
        ),
    ),
    WorkflowChain(
        chain_id="nuclei_lite",
        name="Nuclei Lite",
        category="web",
        description=(
            "Prepare nuclei templates, enforce signed-template and severity policy, "
            "then run a scoped rate-limited scan."
        ),
        selection_categories=("web", "nuclei"),
        trigger_keywords=(
            "nuclei",
            "template",
            "templates",
            "signed",
            "severity",
            "cve",
            "misconfig",
            "rate limit",
            "vulnerability scan",
        ),
        file_suffixes=(".yaml", ".yml", ".txt"),
        target_hints=("url", "host"),
        prerequisites=(
            _SCOPE_PREREQ,
            "Template directory or update policy is known.",
            "Allowed severities are selected before scan planning.",
        ),
        safety_notes=(
            _SCOPE_SAFETY,
            "Template updates must be explicit; never auto-update during offline runs.",
        ),
        steps=(
            _step(
                "template-status",
                "nuclei",
                "Record local template path, age, and signed-template policy.",
                _params(
                    ("templates_dir", "{nuclei_templates_dir}"),
                    ("update_allowed", "{allow_template_update:false}"),
                    ("signed_templates_only", "{signed_templates_only:true}"),
                ),
                ("Nuclei template storage location is known.",),
                ("Do not fetch or update templates unless explicitly authorized."),
                ("template_status",),
            ),
            _step(
                "select-templates",
                "nuclei",
                "Select tags and severity levels appropriate to the challenge.",
                _params(
                    ("severity", "{severity:low,medium,high,critical}"),
                    ("tags", "{tags:cves,exposure,misconfig}"),
                    ("exclude_tags", "{exclude_tags:dos,intrusive}"),
                ),
                ("Template status has been reviewed.",),
                ("Exclude intrusive or denial-of-service templates by default."),
                ("template_policy",),
            ),
            _step(
                "scope-check",
                "check_target_scope",
                "Confirm every URL in the scan list is authorized.",
                _params(("targets", "{target_or_url_list}")),
                ("Target list is normalized.",),
                ("Block out-of-scope targets before any network-capable tool is run."),
                ("scope_check",),
            ),
            _step(
                "run-rate-limited",
                "nuclei",
                "Run selected templates with bounded rate, retries, and timeout.",
                _params(
                    ("target", "{target_or_url_list}"),
                    ("rate_limit", "{rate_limit:5}"),
                    ("concurrency", "{concurrency:5}"),
                    ("timeout", "{timeout_seconds:5}"),
                    ("output", "{workspace}/web/nuclei.jsonl"),
                ),
                (_SCOPE_PREREQ, "Template policy is selected."),
                (_SCOPE_SAFETY, "Keep retries and concurrency low for shared targets."),
                ("nuclei_findings",),
            ),
            _step(
                "review-findings",
                "manual-review",
                "Group nuclei findings by severity and identify reproducible checks.",
                _params(
                    ("input", "{workspace}/web/nuclei.jsonl"),
                    ("output", "{workspace}/web/nuclei-review.md"),
                ),
                ("Nuclei output exists.",),
                ("Verify findings manually before escalating scan intensity."),
                ("nuclei_review",),
            ),
        ),
    ),
    WorkflowChain(
        chain_id="crawler_endpoint_discovery",
        name="Crawler Endpoint Discovery",
        category="web",
        description="Crawl pages and JavaScript to find endpoints before fuzzing.",
        selection_categories=("web", "crawler", "crawl"),
        trigger_keywords=(
            "crawl",
            "crawler",
            "endpoint",
            "route",
            "javascript",
            "sitemap",
            "link",
            "single page app",
            "spa",
        ),
        file_suffixes=(".html", ".js", ".map", ".har"),
        target_hints=("url",),
        prerequisites=(
            _SCOPE_PREREQ,
            "A base URL is known.",
            "Robots, sitemap, or JavaScript assets may exist.",
        ),
        safety_notes=(
            _SCOPE_SAFETY,
            "Crawl depth and concurrency stay bounded before fuzzing.",
        ),
        steps=(
            _step(
                "seed-urls",
                "httpx",
                "Normalize base URL, redirects, title, and technology metadata.",
                _params(
                    ("input", "{base_url}"),
                    ("follow_redirects", "{follow_redirects:true}"),
                    ("output", "{workspace}/web/crawl-seeds.jsonl"),
                ),
                (_SCOPE_PREREQ, "Base URL is in scope."),
                (_SCOPE_SAFETY, "Use a single seed host unless scope allows more."),
                ("crawl_seeds",),
            ),
            _step(
                "crawl-links",
                "katana",
                "Collect linked endpoints, forms, and JavaScript references.",
                _params(
                    ("url", "{base_url}"),
                    ("depth", "{depth:2}"),
                    ("rate_limit", "{rate_limit:5}"),
                    ("output", "{workspace}/web/katana-endpoints.txt"),
                ),
                (_SCOPE_PREREQ, "Crawl depth is selected."),
                (_SCOPE_SAFETY, "Stay on the authorized host unless scope says otherwise."),
                ("endpoint_list", "javascript_assets"),
            ),
            _step(
                "parse-javascript",
                "linkfinder",
                "Extract API paths and hidden routes from downloaded JavaScript.",
                _params(
                    ("input", "{workspace}/web/javascript-assets.txt"),
                    ("output", "{workspace}/web/js-endpoints.txt"),
                ),
                ("JavaScript asset URLs are known.",),
                ("Inspect downloaded scripts locally; do not execute challenge code."),
                ("javascript_endpoints",),
            ),
            _step(
                "dedupe-probe",
                "httpx",
                "Probe deduplicated endpoints for status, content length, and titles.",
                _params(
                    ("input", "{workspace}/web/all-endpoints.txt"),
                    ("threads", "{threads:10}"),
                    ("output", "{workspace}/web/probed-endpoints.jsonl"),
                ),
                (_SCOPE_PREREQ, "Endpoint list is deduplicated."),
                (_SCOPE_SAFETY, "Filter endpoints to the saved target scope."),
                ("live_endpoints",),
            ),
            _step(
                "fuzz-candidates",
                "ffuf",
                "Use crawler findings as seeds for focused fuzzing.",
                _params(
                    ("url_template", "{base_url}/FUZZ"),
                    ("wordlist", "{workspace}/web/path-candidates.txt"),
                    ("output", "{workspace}/web/crawler-ffuf.json"),
                ),
                ("Live endpoint list exists.",),
                ("Fuzz only likely path segments and keep rates conservative."),
                ("focused_fuzz_results",),
            ),
        ),
    ),
    WorkflowChain(
        chain_id="xss_discovery",
        name="XSS Discovery",
        category="web",
        description="Find reflected, stored, and DOM XSS candidates safely.",
        selection_categories=("web", "xss"),
        trigger_keywords=(
            "xss",
            "cross site",
            "reflected",
            "stored",
            "dom",
            "script",
            "payload",
            "html injection",
        ),
        file_suffixes=(".html", ".js", ".har"),
        target_hints=("url",),
        prerequisites=(
            _SCOPE_PREREQ,
            "Candidate endpoints or forms are known.",
            "Payloads are non-destructive proof strings.",
        ),
        safety_notes=(
            _SCOPE_SAFETY,
            "Use harmless marker payloads and avoid account-impacting actions.",
        ),
        steps=(
            _step(
                "collect-inputs",
                "katana",
                "Collect forms, query parameters, and JavaScript sinks.",
                _params(
                    ("url", "{base_url}"),
                    ("depth", "{depth:2}"),
                    ("output", "{workspace}/web/xss-inputs.json"),
                ),
                (_SCOPE_PREREQ, "Base URL is in scope."),
                (_SCOPE_SAFETY, "Keep crawl bounded and same-origin by default."),
                ("input_points",),
            ),
            _step(
                "reflect-markers",
                "ffuf",
                "Inject unique markers to identify reflected parameters.",
                _params(
                    ("url_template", "{endpoint_with_parameter_fuzz}"),
                    ("payload_marker", "{marker:ctfsolver_xss_probe}"),
                    ("output", "{workspace}/web/xss-reflection.json"),
                ),
                ("Candidate parameters are known.",),
                ("Use inert markers before testing any executable payload."),
                ("reflected_parameters",),
            ),
            _step(
                "dom-sink-review",
                "manual-review",
                "Review JavaScript for DOM sinks and source-to-sink flows.",
                _params(
                    ("javascript_inputs", "{workspace}/web/javascript-assets.txt"),
                    ("output", "{workspace}/web/dom-xss-notes.md"),
                ),
                ("JavaScript assets are downloaded or listed.",),
                ("Review code statically; do not execute untrusted scripts locally."),
                ("dom_sink_notes",),
            ),
            _step(
                "xss-template-pass",
                "nuclei",
                "Run selected XSS templates with severity and rate controls.",
                _params(
                    ("target", "{base_url_or_endpoint_list}"),
                    ("tags", "{tags:xss}"),
                    ("rate_limit", "{rate_limit:3}"),
                    ("output", "{workspace}/web/xss-nuclei.jsonl"),
                ),
                (_SCOPE_PREREQ, "Template policy excludes intrusive checks."),
                (_SCOPE_SAFETY, "Review template behavior before autonomous use."),
                ("xss_template_findings",),
            ),
            _step(
                "manual-reproduction",
                "manual-review",
                "Record exact request, payload, context, and screenshot needs.",
                _params(
                    ("inputs", "{workspace}/web/xss-*"),
                    ("output", "{workspace}/web/xss-reproduction.md"),
                ),
                ("Candidate XSS finding exists.",),
                ("Avoid payloads that affect other users or persistent state."),
                ("xss_reproduction_notes",),
            ),
        ),
    ),
    WorkflowChain(
        chain_id="parameter_discovery",
        name="Parameter Discovery",
        category="web",
        description="Discover hidden query, body, and header parameters.",
        selection_categories=("web", "params", "parameters"),
        trigger_keywords=(
            "parameter",
            "parameters",
            "params",
            "query",
            "form",
            "hidden parameter",
            "body",
            "header",
            "arjun",
        ),
        file_suffixes=(".har", ".http", ".json", ".html"),
        target_hints=("url",),
        prerequisites=(
            _SCOPE_PREREQ,
            "Stable endpoints are known from recon or crawler output.",
        ),
        safety_notes=(
            _SCOPE_SAFETY,
            "Prefer GET and low-impact body probes before state-changing requests.",
        ),
        steps=(
            _step(
                "endpoint-baseline",
                "httpx",
                "Capture baseline status, length, and redirect behavior for endpoints.",
                _params(
                    ("input", "{endpoint_list}"),
                    ("output", "{workspace}/web/parameter-baseline.jsonl"),
                ),
                (_SCOPE_PREREQ, "Endpoint list is in scope."),
                (_SCOPE_SAFETY, "Normalize one host at a time unless scope is broader."),
                ("endpoint_baseline",),
            ),
            _step(
                "common-params",
                "arjun",
                "Probe for common query and body parameter names.",
                _params(
                    ("url", "{endpoint}"),
                    ("method", "{method:GET}"),
                    ("stable", "{stable:true}"),
                    ("output", "{workspace}/web/arjun.json"),
                ),
                ("Baseline response profile exists.",),
                ("Avoid destructive methods unless challenge rules permit them."),
                ("candidate_parameters",),
            ),
            _step(
                "wordlist-params",
                "ffuf",
                "Fuzz small parameter lists and compare response deltas.",
                _params(
                    ("url_template", "{endpoint}?FUZZ={marker}"),
                    ("wordlist", "{wordlist:parameters_small}"),
                    ("filters", "{filters:baseline_length,status}"),
                    ("output", "{workspace}/web/parameter-ffuf.json"),
                ),
                ("Baseline and parameter wordlist are selected.",),
                (_SCOPE_SAFETY, "Bound request volume and dedupe endpoints."),
                ("parameter_deltas",),
            ),
            _step(
                "header-params",
                "ffuf",
                "Probe selected headers that commonly change routing or auth logic.",
                _params(
                    ("header_template", "{header_name}: FUZZ"),
                    ("wordlist", "{wordlist:headers_small}"),
                    ("output", "{workspace}/web/header-params.json"),
                ),
                ("Endpoint tolerates safe requests.",),
                ("Do not spoof source IP or auth headers outside challenge rules."),
                ("header_parameter_candidates",),
            ),
            _step(
                "rank-params",
                "manual-review",
                "Rank candidates by response delta and link them to exploit hypotheses.",
                _params(
                    ("inputs", "{workspace}/web/*param*.json"),
                    ("output", "{workspace}/web/parameter-summary.md"),
                ),
                ("Parameter probe outputs exist.",),
                ("Treat noisy deltas as leads, not confirmed vulnerabilities."),
                ("parameter_summary",),
            ),
        ),
    ),
    WorkflowChain(
        chain_id="secret_leak",
        name="Secret Leak Checks",
        category="web",
        description=(
            "Check downloaded source, exposed git data, backups, and repo-style "
            "challenge files for secrets."
        ),
        selection_categories=("web", "secrets", "secret", "source"),
        trigger_keywords=(
            "secret",
            "secrets",
            "leak",
            "token",
            "credential",
            "password",
            "source",
            "repo",
            "repository",
            ".git",
            "backup",
            "bak",
            "env",
        ),
        file_suffixes=(
            ".zip",
            ".tar",
            ".gz",
            ".7z",
            ".bak",
            ".old",
            ".env",
            ".py",
            ".js",
            ".php",
        ),
        target_hints=("url", "file"),
        prerequisites=(
            "Downloaded source, archive, or URL target is available.",
            "Remote checks require authorized target scope.",
        ),
        safety_notes=(
            "Do not publish, print, or commit recovered credentials.",
            "Keep extraction and scans inside the challenge workspace.",
        ),
        steps=(
            _step(
                "backup-paths",
                "ffuf",
                "Check common backup, archive, and source disclosure paths.",
                _params(
                    ("url_template", "{base_url}/FUZZ"),
                    ("wordlist", "{wordlist:backup_paths_small}"),
                    ("output", "{workspace}/web/backup-paths.json"),
                ),
                (_SCOPE_PREREQ, "A base URL is known for remote checks."),
                (_SCOPE_SAFETY, "Use a small disclosure wordlist first."),
                ("backup_path_candidates",),
            ),
            _step(
                "git-exposure",
                "git-dumper",
                "Plan safe recovery of exposed .git metadata when challenge-owned.",
                _params(
                    ("url", "{base_url}/.git/"),
                    ("output_dir", "{workspace}/web/git-dump"),
                ),
                (_SCOPE_PREREQ, "The .git path appears exposed."),
                (
                    _SCOPE_SAFETY,
                    "Recover only from challenge targets and avoid external remotes.",
                ),
                ("git_metadata",),
            ),
            _step(
                "archive-inventory",
                "file",
                "Identify downloaded archives, backups, and source bundles.",
                _params(
                    ("input", "{challenge_dir}"),
                    ("output", "{workspace}/secrets/file-inventory.txt"),
                ),
                (_LOCAL_FILE_PREREQ,),
                (_LOCAL_FILE_SAFETY,),
                ("source_inventory",),
            ),
            _step(
                "secret-patterns",
                "gitleaks",
                "Scan local source and recovered repo data for high-signal secrets.",
                _params(
                    ("path", "{source_or_repo_dir}"),
                    ("redact", "{redact:true}"),
                    ("output", "{workspace}/secrets/gitleaks.json"),
                ),
                ("Source tree or recovered repository exists.",),
                ("Redact secret values in logs and reports."),
                ("secret_candidates",),
            ),
            _step(
                "history-review",
                "git",
                "Review commit history, deleted files, and config for challenge clues.",
                _params(
                    ("repo_dir", "{repo_dir}"),
                    ("output", "{workspace}/secrets/git-history-notes.md"),
                ),
                ("Recovered repository metadata exists.",),
                ("Do not fetch remote refs or push recovered repositories."),
                ("git_history_notes",),
            ),
            _step(
                "rank-secrets",
                "manual-review",
                "Rank candidate keys, tokens, configs, and backups by exploit value.",
                _params(
                    ("inputs", "{workspace}/secrets/*"),
                    ("output", "{workspace}/secrets/secret-summary.md"),
                ),
                ("Secret scan outputs exist.",),
                ("Confirm that any credential use stays within challenge scope."),
                ("secret_summary",),
            ),
        ),
    ),
    WorkflowChain(
        chain_id="api_testing",
        name="API Testing",
        category="web",
        description="Test OpenAPI, JWT, GraphQL, auth, and session behavior.",
        selection_categories=("web", "api"),
        trigger_keywords=(
            "api",
            "openapi",
            "swagger",
            "graphql",
            "jwt",
            "bearer",
            "auth",
            "session",
            "cookie",
            "rest",
        ),
        file_suffixes=(".json", ".yaml", ".yml", ".graphql", ".http", ".har"),
        target_hints=("url",),
        prerequisites=(
            _SCOPE_PREREQ,
            "API base URL or captured requests are available.",
            "Any provided tokens are challenge-owned.",
        ),
        safety_notes=(
            _SCOPE_SAFETY,
            "Avoid destructive API methods unless explicitly part of the challenge.",
            "Never print live credentials in logs.",
        ),
        steps=(
            _step(
                "discover-spec",
                "ffuf",
                "Find OpenAPI, Swagger, GraphQL, and documentation endpoints.",
                _params(
                    ("url_template", "{base_url}/FUZZ"),
                    ("wordlist", "{wordlist:api_discovery_small}"),
                    ("output", "{workspace}/api/spec-discovery.json"),
                ),
                (_SCOPE_PREREQ, "API base URL is known."),
                (_SCOPE_SAFETY, "Use a short API discovery wordlist first."),
                ("api_spec_candidates",),
            ),
            _step(
                "schema-review",
                "manual-review",
                "Extract routes, methods, auth schemes, models, and hidden fields.",
                _params(
                    ("spec_file", "{openapi_or_graphql_schema}"),
                    ("output", "{workspace}/api/schema-notes.md"),
                ),
                ("API schema or captured requests are available.",),
                ("Review schemas locally before active testing."),
                ("api_schema_notes",),
            ),
            _step(
                "jwt-review",
                "jwt_tool",
                "Inspect JWT claims, algorithms, key IDs, and common weaknesses.",
                _params(
                    ("token", "{jwt_token}"),
                    ("target", "{api_endpoint_optional}"),
                    ("output", "{workspace}/api/jwt-review.json"),
                ),
                ("JWT token is challenge-owned and authorized to inspect."),
                ("Do not brute force secrets without explicit challenge permission."),
                ("jwt_findings",),
            ),
            _step(
                "graphql-checks",
                "graphql-cop",
                "Check introspection, batching, auth bypass, and resolver hints.",
                _params(
                    ("endpoint", "{graphql_endpoint}"),
                    ("headers", "{headers_optional}"),
                    ("output", "{workspace}/api/graphql-checks.json"),
                ),
                (_SCOPE_PREREQ, "GraphQL endpoint is in scope."),
                (_SCOPE_SAFETY, "Keep query depth and batching conservative."),
                ("graphql_findings",),
            ),
            _step(
                "contract-tests",
                "schemathesis",
                "Generate low-impact tests from OpenAPI examples and constraints.",
                _params(
                    ("schema", "{openapi_schema}"),
                    ("base_url", "{base_url}"),
                    ("checks", "{checks:not_a_server_error,status_code_conformance}"),
                    ("output", "{workspace}/api/contract-tests.json"),
                ),
                ("OpenAPI schema and base URL are known."),
                ("Disable state-changing or destructive tests by default."),
                ("contract_test_findings",),
            ),
            _step(
                "session-diff",
                "manual-review",
                "Compare anonymous, low-privilege, and challenge-provided sessions.",
                _params(
                    ("captures", "{workspace}/api/session-captures"),
                    ("output", "{workspace}/api/session-diff.md"),
                ),
                ("At least two authorized session contexts are available."),
                ("Do not test other users or real third-party identities."),
                ("session_findings",),
            ),
        ),
    ),
    WorkflowChain(
        chain_id="pcap_triage",
        name="PCAP Triage",
        category="forensics",
        description=(
            "Summarize protocols, extract objects and credentials, inspect DNS and "
            "USB HID anomalies, then build a timeline."
        ),
        selection_categories=("forensics", "pcap", "network-forensics"),
        trigger_keywords=(
            "pcap",
            "pcapng",
            "packet",
            "traffic",
            "capture",
            "wireshark",
            "tshark",
            "dns",
            "usb",
            "hid",
            "credentials",
        ),
        file_suffixes=(".pcap", ".pcapng", ".cap"),
        target_hints=("file",),
        prerequisites=(
            _LOCAL_FILE_PREREQ,
            "The capture file hash is recorded before extraction.",
        ),
        safety_notes=(
            _LOCAL_FILE_SAFETY,
            "Analyze captures offline unless challenge rules require a live service.",
        ),
        steps=(
            _step(
                "capture-metadata",
                "capinfos",
                "Record capture format, packet count, duration, and timestamps.",
                _params(
                    ("pcap", "{pcap_file}"),
                    ("output", "{workspace}/pcap/capture-metadata.txt"),
                ),
                (_LOCAL_FILE_PREREQ,),
                (_LOCAL_FILE_SAFETY,),
                ("capture_metadata",),
            ),
            _step(
                "protocol-summary",
                "tshark",
                "Summarize conversations, protocol hierarchy, endpoints, and IO stats.",
                _params(
                    ("pcap", "{pcap_file}"),
                    ("stats", "{stats:conv,io,phs,endpoints}"),
                    ("output", "{workspace}/pcap/protocol-summary.txt"),
                ),
                ("Capture metadata exists.",),
                ("Do not replay traffic during triage."),
                ("protocol_summary",),
            ),
            _step(
                "credential-search",
                "tshark",
                "Extract HTTP auth, FTP, SMTP, cookies, and obvious credential fields.",
                _params(
                    ("pcap", "{pcap_file}"),
                    ("display_filter", "{filter:credentials_or_cookies}"),
                    ("output", "{workspace}/pcap/credential-candidates.json"),
                ),
                ("Protocol summary identifies application traffic."),
                ("Redact credentials in shared reports until confirmed challenge-only."),
                ("credential_candidates",),
            ),
            _step(
                "extract-objects",
                "tshark",
                "Extract HTTP, SMB, FTP, and other supported transferred objects.",
                _params(
                    ("pcap", "{pcap_file}"),
                    ("object_types", "{object_types:http,smb,ftp}"),
                    ("output_dir", "{workspace}/pcap/objects"),
                ),
                ("Capture contains file-transfer protocols."),
                (_LOCAL_FILE_SAFETY,),
                ("extracted_objects",),
            ),
            _step(
                "dns-anomalies",
                "tshark",
                "Review DNS queries, TXT records, long labels, and tunneling patterns.",
                _params(
                    ("pcap", "{pcap_file}"),
                    ("display_filter", "{filter:dns}"),
                    ("output", "{workspace}/pcap/dns-anomalies.tsv"),
                ),
                ("DNS traffic exists in the capture."),
                ("Avoid resolving captured domains during offline triage."),
                ("dns_anomalies",),
            ),
            _step(
                "usb-hid",
                "usb_hid_extract",
                "Decode USB HID keyboard traffic when present.",
                _params(
                    ("pcap", "{pcap_file}"),
                    ("mode", "{mode:keyboard}"),
                    ("output", "{workspace}/pcap/usb-hid.txt"),
                ),
                ("USB HID packets are present or suspected."),
                ("Keep decoded keystrokes in challenge evidence only."),
                ("usb_hid_text",),
            ),
            _step(
                "timeline",
                "tshark",
                "Build a timeline of notable requests, transfers, credentials, and DNS.",
                _params(
                    ("pcap", "{pcap_file}"),
                    ("fields", "{fields:frame.time,ip.src,ip.dst,protocol,info}"),
                    ("output", "{workspace}/pcap/timeline.tsv"),
                ),
                ("Notable packets or extracted objects exist."),
                ("Preserve original timestamps and avoid editing raw captures."),
                ("pcap_timeline",),
            ),
        ),
    ),
    WorkflowChain(
        chain_id="stego_triage",
        name="Stego Triage",
        category="forensics",
        description=(
            "Chain metadata, strings, carving, image/audio stego, passworded "
            "extractors, and spectrogram analysis."
        ),
        selection_categories=("forensics", "stego", "steganography"),
        trigger_keywords=(
            "stego",
            "steganography",
            "hidden",
            "lsb",
            "image",
            "audio",
            "spectrogram",
            "png",
            "jpg",
            "jpeg",
            "bmp",
            "wav",
            "append",
        ),
        file_suffixes=(".png", ".jpg", ".jpeg", ".bmp", ".gif", ".wav", ".flac", ".mp3"),
        target_hints=("file",),
        prerequisites=(
            _LOCAL_FILE_PREREQ,
            "Original artifact hash is recorded before extraction.",
        ),
        safety_notes=(
            _LOCAL_FILE_SAFETY,
            "Never overwrite the original artifact; write derived files separately.",
        ),
        steps=(
            _step(
                "file-metadata",
                "file",
                "Identify file type, embedded data, and parser hints.",
                _params(
                    ("input", "{artifact_file}"),
                    ("output", "{workspace}/stego/file-metadata.txt"),
                ),
                (_LOCAL_FILE_PREREQ,),
                (_LOCAL_FILE_SAFETY,),
                ("file_metadata",),
            ),
            _step(
                "exif-metadata",
                "exiftool",
                "Extract metadata, comments, thumbnails, and suspicious fields.",
                _params(
                    ("input", "{artifact_file}"),
                    ("json", "{json:true}"),
                    ("output", "{workspace}/stego/exiftool.json"),
                ),
                (_LOCAL_FILE_PREREQ,),
                ("Run metadata extraction read-only and keep originals intact.",),
                ("metadata_fields",),
            ),
            _step(
                "strings",
                "strings",
                "Search printable strings for flags, passwords, URLs, and hints.",
                _params(
                    ("input", "{artifact_file}"),
                    ("min_length", "{min_length:5}"),
                    ("output", "{workspace}/stego/strings.txt"),
                ),
                (_LOCAL_FILE_PREREQ,),
                ("Do not assume string hits are decoded flags without validation."),
                ("string_hints",),
            ),
            _step(
                "carve",
                "binwalk",
                "Carve appended files, compressed streams, and embedded payloads.",
                _params(
                    ("input", "{artifact_file}"),
                    ("extract", "{extract:true}"),
                    ("output_dir", "{workspace}/stego/binwalk"),
                ),
                (_LOCAL_FILE_PREREQ,),
                (_LOCAL_FILE_SAFETY,),
                ("carved_files",),
            ),
            _step(
                "image-lsb",
                "zsteg",
                "Check common PNG/BMP bit planes and channel orders.",
                _params(
                    ("input", "{image_file}"),
                    ("mode", "{mode:all_safe}"),
                    ("output", "{workspace}/stego/zsteg.txt"),
                ),
                ("Artifact is a supported image format."),
                ("Limit extraction size and inspect output before recursive processing."),
                ("lsb_candidates",),
            ),
            _step(
                "passworded-stego",
                "stegseek",
                "Try challenge wordlists against steghide-compatible artifacts.",
                _params(
                    ("input", "{jpeg_or_wav_file}"),
                    ("wordlist", "{wordlist:challenge_words}"),
                    ("output", "{workspace}/stego/stegseek.txt"),
                ),
                ("Artifact format and challenge wordlist are selected."),
                ("Use challenge-specific wordlists before broad cracking."),
                ("stegseek_result",),
            ),
            _step(
                "audio-spectrogram",
                "sox",
                "Generate spectrograms and audio stats for visual or SSTV-style clues.",
                _params(
                    ("input", "{audio_file}"),
                    ("output", "{workspace}/stego/spectrogram.png"),
                ),
                ("Artifact is audio or carved audio data exists."),
                ("Generate derived images only; do not modify original audio."),
                ("spectrogram",),
            ),
            _step(
                "triage-summary",
                "manual-review",
                "Collect decoded candidates, extracted files, and next hypotheses.",
                _params(
                    ("inputs", "{workspace}/stego/*"),
                    ("output", "{workspace}/stego/stego-summary.md"),
                ),
                ("At least one stego pass has completed."),
                ("Record exact extraction path for reproducibility."),
                ("stego_summary",),
            ),
        ),
    ),
)


_CHAIN_BY_ID = {chain.chain_id: chain for chain in WORKFLOW_CHAINS}

_CATEGORY_ALIASES = {
    "api testing": "api",
    "crawl": "crawler",
    "crawler": "crawler",
    "forensic": "forensics",
    "forensics": "forensics",
    "network forensics": "pcap",
    "packet": "pcap",
    "params": "params",
    "parameter": "params",
    "parameters": "params",
    "recon": "recon",
    "secret": "secret",
    "secret leak": "secret",
    "secrets": "secret",
    "steganography": "stego",
    "web": "web",
    "xss": "xss",
}


def get_workflow_chain(chain_id: str) -> dict[str, Any]:
    """Return one workflow chain by id as a plain dictionary."""

    return _CHAIN_BY_ID[chain_id].to_dict()


def list_workflow_chains() -> list[dict[str, Any]]:
    """Return every declarative chain in stable order."""

    return [chain.to_dict() for chain in WORKFLOW_CHAINS]


def select_workflow_chains(
    description: str = "",
    category: str = "",
    target: str = "",
    files: Iterable[Any] | None = None,
    findings: Iterable[Any] | Mapping[str, Any] | str | None = None,
    limit: int = 10,
    min_score: int = 1,
) -> list[dict[str, Any]]:
    """Select matching workflow chains from challenge signals.

    Selection is deterministic and side-effect free. Returned dictionaries
    include ``score`` and ``reasons`` plus the chain metadata.
    """

    file_names = [str(item) for item in _flatten(files)]
    finding_text = [str(item) for item in _flatten(findings)]
    raw_category = str(category or "")
    normalized_category = _normalize_category(raw_category)
    context = " ".join(
        part
        for part in [description, raw_category, target, *file_names, *finding_text]
        if part
    ).lower()
    target_kind = _target_kind(target)

    matches: list[dict[str, Any]] = []
    for chain in WORKFLOW_CHAINS:
        score = 0
        reasons: list[str] = []

        if normalized_category and normalized_category in chain.selection_categories:
            score += 24
            reasons.append(f"category:{normalized_category}")
        elif normalized_category == chain.category:
            score += 14
            reasons.append(f"category:{normalized_category}")

        if target_kind in chain.target_hints:
            score += 8
            reasons.append(f"target:{target_kind}")

        suffix_matches = _matching_suffixes(file_names, chain.file_suffixes)
        if suffix_matches:
            score += 18 + min(6, len(suffix_matches) * 2)
            reasons.append("file_suffix:" + ",".join(suffix_matches[:3]))

        keyword_matches = [
            keyword
            for keyword in chain.trigger_keywords
            if _keyword_matches(keyword, context)
        ]
        if keyword_matches:
            score += min(30, len(keyword_matches) * 5)
            reasons.append("keyword:" + ",".join(keyword_matches[:3]))

        if score < min_score:
            continue

        item = chain.to_dict()
        item["score"] = score
        item["reasons"] = sorted(reasons)
        matches.append(item)

    matches.sort(key=lambda item: (-int(item["score"]), str(item["chain_id"])))
    return matches[: max(0, limit)]


def validate_workflow_chains(
    chains: Iterable[WorkflowChain] = WORKFLOW_CHAINS,
) -> list[str]:
    """Return metadata validation errors for workflow chains."""

    errors: list[str] = []
    seen_ids: set[str] = set()
    for chain in chains:
        prefix = f"chain {chain.chain_id!r}"
        if not chain.chain_id:
            errors.append("chain id is required")
        if chain.chain_id in seen_ids:
            errors.append(f"{prefix}: duplicate chain id")
        seen_ids.add(chain.chain_id)
        if not chain.name or not chain.category or not chain.description:
            errors.append(f"{prefix}: name, category, and description are required")
        if not chain.prerequisites:
            errors.append(f"{prefix}: prerequisites are required")
        if not chain.safety_notes:
            errors.append(f"{prefix}: safety_notes are required")
        if not chain.steps:
            errors.append(f"{prefix}: at least one step is required")

        seen_step_ids: set[str] = set()
        for step in chain.steps:
            step_prefix = f"{prefix} step {step.step_id!r}"
            if step.step_id in seen_step_ids:
                errors.append(f"{step_prefix}: duplicate step id")
            seen_step_ids.add(step.step_id)
            if not step.step_id or not step.tool or not step.purpose:
                errors.append(f"{step_prefix}: step_id, tool, and purpose are required")
            if not step.parameter_templates:
                errors.append(f"{step_prefix}: parameter_templates are required")
            if not step.prerequisites:
                errors.append(f"{step_prefix}: prerequisites are required")
            if not step.safety_notes:
                errors.append(f"{step_prefix}: safety_notes are required")
    return errors


def _normalize_category(category: str) -> str:
    normalized = " ".join(category.strip().lower().replace("_", " ").split())
    return _CATEGORY_ALIASES.get(normalized, normalized)


def _target_kind(target: str) -> str:
    text = target.strip().lower()
    if not text:
        return ""
    if text.startswith(("http://", "https://")):
        return "url"
    if "." in text or ":" in text:
        return "host"
    return "file"


def _matching_suffixes(
    file_names: Iterable[str],
    suffixes: tuple[str, ...],
) -> list[str]:
    matches: list[str] = []
    suffix_set = set(suffixes)
    for file_name in file_names:
        lower_name = file_name.lower()
        suffix = PurePath(lower_name).suffix
        if suffix in suffix_set and suffix not in matches:
            matches.append(suffix)
        if lower_name.endswith(".git") and ".git" in suffix_set and ".git" not in matches:
            matches.append(".git")
    return matches


def _keyword_matches(keyword: str, context: str) -> bool:
    if any(not char.isalnum() and char != "_" for char in keyword):
        return keyword in context
    pattern = rf"(?<![a-z0-9_]){re.escape(keyword)}(?![a-z0-9_])"
    return re.search(pattern, context) is not None


def _flatten(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, (str, bytes, PurePath)):
        return [value]
    if isinstance(value, Mapping):
        flattened: list[Any] = []
        for key, nested in value.items():
            flattened.append(key)
            flattened.extend(_flatten(nested))
        return flattened
    if isinstance(value, Iterable):
        flattened = []
        for nested in value:
            flattened.extend(_flatten(nested))
        return flattened
    return [value]


__all__ = [
    "WORKFLOW_CHAINS",
    "WorkflowChain",
    "WorkflowStep",
    "get_workflow_chain",
    "list_workflow_chains",
    "select_workflow_chains",
    "validate_workflow_chains",
]
