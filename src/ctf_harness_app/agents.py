from __future__ import annotations

import json
import os
import selectors  # noqa: F401 - kept for backwards-compat; run_streaming_agent uses threading now
import shlex
import shutil
import subprocess
import time
from pathlib import Path

from .config import DEFAULT_CODEX_MODEL, DEFAULT_CTF_IMAGE, DEFAULT_DOCKERFILE, DEFAULT_KIRO_MODEL, DEFAULT_OPENCODE_MODEL, load_dotenv
from .iam_key_pool import IamKey, load_pool, pool_region, select_key_for
from .workspace import build_followup_prompt, load_challenge, record_run_finish, record_run_heartbeat, record_run_start
from .util import HarnessError


PROMPT_FILENAME = ".ctf-harness-current-prompt.md"
NO_OUTPUT_NOTICE_SECONDS = 60
OUTPUT_BUFFER_LIMIT = 500_000
AGENT_MCP_SERVER_NAME = "ctfsolver"


def host_codex_auth_path() -> Path:
    home = os.environ.get("CTF_HARNESS_CODEX_HOME") or os.environ.get("CODEX_HOME")
    return Path(home).expanduser() / "auth.json" if home else Path.home() / ".codex" / "auth.json"


def host_claude_config_dir() -> Path:
    home = os.environ.get("CTF_HARNESS_CLAUDE_CONFIG_DIR") or os.environ.get("CLAUDE_CONFIG_DIR")
    return Path(home).expanduser() if home else Path.home() / ".claude"


def host_claude_credentials_path() -> Path:
    return host_claude_config_dir() / ".credentials.json"


def prepare_claude_auth_env() -> None:
    if not os.environ.get("ANTHROPIC_AUTH_TOKEN") and os.environ.get("CLAUDE_CODE_OAUTH_TOKEN"):
        os.environ["ANTHROPIC_AUTH_TOKEN"] = os.environ["CLAUDE_CODE_OAUTH_TOKEN"]


def prepare_codex_auth_env() -> None:
    if os.environ.get("CODEX_ACCESS_TOKEN"):
        return
    for alias in ("OPENAI_OAUTH_TOKEN", "CODEX_OAUTH_TOKEN"):
        if os.environ.get(alias):
            os.environ["CODEX_ACCESS_TOKEN"] = os.environ[alias]
            return


def has_claude_auth() -> bool:
    prepare_claude_auth_env()
    return bool(
        os.environ.get("ANTHROPIC_API_KEY")
        or os.environ.get("ANTHROPIC_AUTH_TOKEN")
        or host_claude_credentials_path().exists()
    )


def has_codex_auth() -> bool:
    prepare_codex_auth_env()
    return bool(os.environ.get("OPENAI_API_KEY") or os.environ.get("CODEX_ACCESS_TOKEN") or host_codex_auth_path().exists())


def claude_env_summary() -> str:
    if os.environ.get("ANTHROPIC_API_KEY"):
        return "ANTHROPIC_API_KEY is set"
    if os.environ.get("ANTHROPIC_AUTH_TOKEN"):
        return "ANTHROPIC_AUTH_TOKEN is set"
    if host_claude_credentials_path().exists():
        return "host Claude .credentials.json is available"
    return "no Claude auth is configured"


def claude_partial_messages_enabled() -> bool:
    value = os.environ.get("CTF_HARNESS_CLAUDE_PARTIAL_MESSAGES", "")
    return value.strip().lower() in {"1", "true", "yes", "on"}


def codex_env_summary() -> str:
    if os.environ.get("OPENAI_API_KEY"):
        return "OPENAI_API_KEY is set"
    if host_codex_auth_path().exists():
        return "host Codex OAuth auth.json is available"
    if os.environ.get("CODEX_ACCESS_TOKEN"):
        return "CODEX_ACCESS_TOKEN is set"
    return "no Codex auth is configured"


def codex_model() -> str:
    model = os.environ.get("CTF_HARNESS_CODEX_MODEL", "").strip() or DEFAULT_CODEX_MODEL
    return model


# ---------------------------------------------------------------------------
# Kiro CLI (Amazon Kiro - AWS Bedrock backed) auth + config
# ---------------------------------------------------------------------------


def host_kiro_config_dir() -> Path:
    home = os.environ.get("CTF_HARNESS_KIRO_CONFIG_DIR") or os.environ.get("KIRO_CONFIG_DIR")
    return Path(home).expanduser() if home else Path.home() / ".kiro"


def host_kiro_secrets_path() -> Path:
    return host_kiro_config_dir() / "secrets.json"


def host_kiro_data_dir() -> Path:
    """Directory holding Kiro CLI's real auth store (data.sqlite3).

    Windows: %LOCALAPPDATA%\\Kiro-Cli\\  (e.g. C:\\Users\\<u>\\AppData\\Local\\Kiro-Cli)
    Linux/macOS: ~/.local/share/kiro-cli/

    Override with CTF_HARNESS_KIRO_DATA_DIR. This directory contains
    data.sqlite3 (auth_kv table holds the actual OIDC access token and SSO
    client registration; without this file Kiro CLI cannot make API calls).
    """
    override = os.environ.get("CTF_HARNESS_KIRO_DATA_DIR")
    if override:
        return Path(override).expanduser()
    if os.name == "nt":
        local_appdata = os.environ.get("LOCALAPPDATA") or (Path.home() / "AppData" / "Local")
        return Path(local_appdata) / "Kiro-Cli"
    return Path.home() / ".local" / "share" / "kiro-cli"


def host_kiro_data_sqlite_path() -> Path:
    return host_kiro_data_dir() / "data.sqlite3"


def host_aws_dir() -> Path:
    return Path.home() / ".aws"


def prepare_kiro_auth_env() -> None:
    # Kiro uses AWS SSO tokens or Bedrock bearer tokens; no aliases to normalize.
    return


def has_kiro_auth() -> bool:
    prepare_kiro_auth_env()
    return bool(
        os.environ.get("KIRO_API_KEY")
        or os.environ.get("AWS_BEARER_TOKEN_BEDROCK")
        or os.environ.get("AWS_PROFILE")
        or host_kiro_data_sqlite_path().exists()
        or host_kiro_secrets_path().exists()
        or (host_aws_dir() / "sso" / "cache").exists()
    )


def kiro_env_summary() -> str:
    if os.environ.get("KIRO_API_KEY"):
        return "KIRO_API_KEY is set"
    if os.environ.get("AWS_BEARER_TOKEN_BEDROCK"):
        return "AWS_BEARER_TOKEN_BEDROCK is set"
    if os.environ.get("AWS_PROFILE"):
        return f"AWS_PROFILE={os.environ['AWS_PROFILE']!r} is set"
    if host_kiro_data_sqlite_path().exists():
        return f"host Kiro data.sqlite3 is available ({host_kiro_data_sqlite_path()})"
    if host_kiro_secrets_path().exists():
        return "host Kiro secrets.json is available (MCP-only; likely NOT enough for chat)"
    if (host_aws_dir() / "sso" / "cache").exists():
        return "host AWS SSO cache is available"
    return "no Kiro auth is configured"


def kiro_model() -> str:
    return os.environ.get("CTF_HARNESS_KIRO_MODEL", "").strip() or DEFAULT_KIRO_MODEL


# ---------------------------------------------------------------------------
# OpenCode CLI (sst/opencode) auth + config
# ---------------------------------------------------------------------------


def host_opencode_auth_path() -> Path:
    home = os.environ.get("CTF_HARNESS_OPENCODE_HOME") or os.environ.get("OPENCODE_HOME")
    if home:
        return Path(home).expanduser() / "auth.json"
    return Path.home() / ".local" / "share" / "opencode" / "auth.json"


def host_opencode_share_dir() -> Path:
    return host_opencode_auth_path().parent


def host_opencode_config_dir() -> Path:
    return Path.home() / ".config" / "opencode"


def prepare_opencode_auth_env() -> None:
    if not os.environ.get("OPENCODE_AUTH_TOKEN") and os.environ.get("OPENCODE_OAUTH_TOKEN"):
        os.environ["OPENCODE_AUTH_TOKEN"] = os.environ["OPENCODE_OAUTH_TOKEN"]


def has_opencode_auth() -> bool:
    prepare_opencode_auth_env()
    return bool(
        os.environ.get("OPENCODE_API_KEY")
        or os.environ.get("OPENCODE_AUTH_TOKEN")
        or os.environ.get("ANTHROPIC_API_KEY")
        or os.environ.get("OPENAI_API_KEY")
        or host_opencode_auth_path().exists()
    )


def opencode_env_summary() -> str:
    if os.environ.get("OPENCODE_API_KEY"):
        return "OPENCODE_API_KEY is set"
    if os.environ.get("OPENCODE_AUTH_TOKEN"):
        return "OPENCODE_AUTH_TOKEN is set"
    if host_opencode_auth_path().exists():
        return "host OpenCode auth.json is available"
    if os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("OPENAI_API_KEY"):
        return "provider API key (Anthropic/OpenAI) is set"
    return "no OpenCode auth is configured"


def opencode_model() -> str:
    return os.environ.get("CTF_HARNESS_OPENCODE_MODEL", "").strip() or DEFAULT_OPENCODE_MODEL


def agent_mcp_url() -> str:
    return os.environ.get("CTF_HARNESS_AGENT_MCP_URL", "").strip()


def agent_mcp_config() -> dict[str, object]:
    url = agent_mcp_url()
    if not url:
        return {"mcpServers": {}}
    return {
        "mcpServers": {
            AGENT_MCP_SERVER_NAME: {
                "type": "http",
                "url": url,
            }
        }
    }


def agent_mcp_config_json() -> str:
    return json.dumps(agent_mcp_config(), separators=(",", ":"))


def claude_allowed_tools() -> str:
    tools = "Bash(*),Read,Write,Edit,Glob,Grep,WebSearch,WebFetch"
    if agent_mcp_url():
        tools += f",mcp__{AGENT_MCP_SERVER_NAME}__*"
    return tools


def write_codex_mcp_config(codex_home: Path) -> None:
    url = agent_mcp_url()
    if not url:
        return
    codex_home.mkdir(parents=True, exist_ok=True)
    config_path = codex_home / "config.toml"
    config_path.write_text(
        f"[mcp_servers.{AGENT_MCP_SERVER_NAME}]\n"
        f"url = {json.dumps(url)}\n",
        encoding="utf-8",
    )


def build_tools_image(
    runtime: str = "docker",
    image: str = DEFAULT_CTF_IMAGE,
    dockerfile: Path = Path(DEFAULT_DOCKERFILE),
) -> int:
    if not dockerfile.exists():
        raise HarnessError(f"Dockerfile not found: {dockerfile}")
    if runtime == "docker":
        command = [
            runtime,
            "buildx",
            "build",
            "--load",
            "-f",
            str(dockerfile),
            "-t",
            image,
            str(dockerfile.parent or "."),
        ]
    else:
        command = [runtime, "build", "-f", str(dockerfile), "-t", image, str(dockerfile.parent or ".")]
    return subprocess.run(
        command,
        check=False,
    ).returncode


def docker_env_args(agent: str = "agent") -> list[str]:
    prepare_claude_auth_env()
    prepare_codex_auth_env()
    prepare_kiro_auth_env()
    prepare_opencode_auth_env()
    args: list[str] = []
    prefer_host_codex_auth = agent == "codex" and host_codex_auth_path().exists()

    # For Bedrock-backed agents (kiro, opencode), pick an IAM key from the pool
    # so concurrent challenges spread across different identities/rate limits.
    # Selection is stable per (challenge, agent) via _iam_pool_key_env() called
    # from docker_command. Here we only forward pre-set env vars; the pool
    # override happens in docker_command via extra `-e KEY=value` args.
    for env_name in (
        "ANTHROPIC_API_KEY",
        "ANTHROPIC_AUTH_TOKEN",
        "CLAUDE_CODE_USE_BEDROCK",
        "CLAUDE_CODE_USE_VERTEX",
        "OPENAI_API_KEY",
        "CODEX_ACCESS_TOKEN",
        "KIRO_API_KEY",
        "AWS_BEARER_TOKEN_BEDROCK",
        "AWS_PROFILE",
        "AWS_REGION",
        "AWS_DEFAULT_REGION",
        "OPENCODE_API_KEY",
        "OPENCODE_AUTH_TOKEN",
    ):
        # Scope leakage of provider-specific creds by agent so tokens don't cross-contaminate.
        if agent == "claude" and env_name in {
            "OPENAI_API_KEY", "CODEX_ACCESS_TOKEN",
            "KIRO_API_KEY", "AWS_BEARER_TOKEN_BEDROCK", "AWS_PROFILE", "AWS_REGION", "AWS_DEFAULT_REGION",
            "OPENCODE_API_KEY", "OPENCODE_AUTH_TOKEN",
        }:
            continue
        if agent == "codex" and (
            env_name.startswith(("ANTHROPIC_", "CLAUDE_CODE_", "KIRO_", "OPENCODE_"))
            or env_name in {"AWS_BEARER_TOKEN_BEDROCK", "AWS_PROFILE", "AWS_REGION", "AWS_DEFAULT_REGION"}
        ):
            continue
        if agent == "kiro" and env_name.startswith(("ANTHROPIC_", "CLAUDE_CODE_", "OPENAI_", "CODEX_", "OPENCODE_")):
            continue
        if agent == "opencode" and (
            env_name.startswith(("CLAUDE_CODE_", "CODEX_", "KIRO_"))
        ):
            # OpenCode CAN use AWS_* creds directly (its bedrock-auth-refresh plugin path);
            # do NOT skip AWS vars for opencode.
            continue
        if prefer_host_codex_auth and env_name == "CODEX_ACCESS_TOKEN":
            continue
        # Skip empty-string env vars — passing e.g. AWS_BEARER_TOKEN_BEDROCK="" to
        # the container makes boto3 try bearer auth and fail. Only forward set-and-nonempty.
        value = os.environ.get(env_name)
        if value:
            args.extend(["-e", f"{env_name}={value}"])
    return args


def iam_pool_env_args(challenge_slug: str, agent: str) -> tuple[list[str], IamKey | None]:
    """Select an IAM key from the pool and return `-e AWS_...` docker args.

    Only fires for agents that actually use direct Bedrock SigV4 (opencode, kiro).
    Returns (args, selected_key). If no pool exists or agent isn't a fit,
    returns ([], None) and the container relies on other auth paths.
    """
    if agent not in {"opencode", "kiro"}:
        return [], None
    keys = load_pool()
    if not keys:
        return [], None
    picked = select_key_for(challenge_slug, agent, keys)
    if picked is None:
        return [], None
    region = pool_region()
    return (
        [
            "-e", f"AWS_ACCESS_KEY_ID={picked.access_key_id}",
            "-e", f"AWS_SECRET_ACCESS_KEY={picked.secret_access_key}",
            "-e", f"AWS_REGION={region}",
            "-e", f"AWS_DEFAULT_REGION={region}",
            # Bedrock plugin sees ABSK-prefixed key to skip SSO; we do NOT have
            # a bearer here, so leave AWS_BEARER_TOKEN_BEDROCK unset (empty
            # string breaks boto3 signing — see prior debugging).
        ],
        picked,
    )


def mask_command(command: list[str]) -> list[str]:
    masked: list[str] = []
    mask_next = False
    sensitive_names = (
        "ANTHROPIC_API_KEY",
        "ANTHROPIC_AUTH_TOKEN",
        "CLAUDE_CODE_OAUTH_TOKEN",
        "OPENAI_API_KEY",
        "OPENAI_OAUTH_TOKEN",
        "CODEX_OAUTH_TOKEN",
        "CODEX_ACCESS_TOKEN",
        "KIRO_API_KEY",
        "AWS_BEARER_TOKEN_BEDROCK",
        "OPENCODE_API_KEY",
        "OPENCODE_AUTH_TOKEN",
        "OPENCODE_OAUTH_TOKEN",
    )
    for part in command:
        if mask_next:
            if any(part.startswith(f"{name}=") for name in sensitive_names):
                masked.append(part.split("=", 1)[0] + "=<set>")
            else:
                masked.append(part)
            mask_next = False
            continue
        masked.append(part)
        if part == "-e":
            mask_next = True
    return masked


def stream_reported_error(output: bytes) -> tuple[bool, str]:
    for raw_line in reversed(output.decode("utf-8", errors="replace").splitlines()):
        line = raw_line.strip()
        if not line.startswith("{"):
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if event.get("type") == "result" and (event.get("is_error") or event.get("api_error_status")):
            message = str(event.get("result") or event.get("subtype") or "agent reported an error")
            return True, message
        if event.get("error"):
            message = str(event.get("result") or event.get("error") or "agent reported an error")
            return True, message
    return False, ""


def claude_inner_command(action: str, prompt_path: str = f"/workspace/{PROMPT_FILENAME}") -> list[str]:
    claude_args = ["claude", "-p"]
    mcp_config = agent_mcp_config_json()
    if os.environ.get("ANTHROPIC_API_KEY"):
        claude_args.extend(["--bare", "--strict-mcp-config", "--mcp-config", mcp_config])
    else:
        claude_args.extend(["--strict-mcp-config", "--mcp-config", mcp_config])
    if action == "continue":
        claude_args.append("--continue")
    claude_args.extend([
        "--permission-mode",
        "dontAsk",
        "--allowedTools",
        claude_allowed_tools(),
        "--output-format",
        "stream-json",
        "--verbose",
    ])
    if claude_partial_messages_enabled():
        claude_args.append("--include-partial-messages")
    base_command = " ".join(shlex.quote(part) for part in claude_args)
    shell_script = (
        "export CLAUDE_CONFIG_DIR=/root/.claude; "
        "export CODEX_HOME=/root/.codex; "
        "export XDG_CACHE_HOME=/root/.cache; "
        "export XDG_STATE_HOME=/root/.local/state; "
        "mkdir -p /root/.claude /root/.codex /root/.cache /root/.local/state; "
        "echo '[ctf-harness] container user:'; id; "
        "echo '[ctf-harness] Claude auth env:'; "
        "env | grep -E '^(ANTHROPIC_API_KEY|ANTHROPIC_AUTH_TOKEN|CLAUDE_CODE_USE_)=' | sed 's/=.*/=<set>/' || true; "
        "echo '[ctf-harness] claude auth status:'; "
        "timeout 8s claude auth status </dev/null 2>&1 || echo '[ctf-harness] claude auth status unavailable or timed out; continuing'; "
        f"exec {base_command} \"$(cat {shlex.quote(prompt_path)})\" </dev/null"
    )
    command = [
        "sh",
        "-lc",
        shell_script,
    ]
    return command


def codex_inner_command(action: str, prompt_path: str = f"/workspace/{PROMPT_FILENAME}") -> list[str]:
    codex_base_args = [
        "--json",
        "--model",
        codex_model(),
        "--dangerously-bypass-approvals-and-sandbox",
        "--skip-git-repo-check",
        "-o",
        "/workspace/codex-last-message.txt",
    ]
    fresh_exec = " ".join(shlex.quote(part) for part in ["codex", "exec", *codex_base_args])
    resume_exec = " ".join(shlex.quote(part) for part in ["codex", "exec", "resume", "--last", *codex_base_args])
    shell_script = (
        "export CODEX_HOME=/root/.codex; "
        "export CLAUDE_CONFIG_DIR=/root/.claude; "
        "export XDG_CACHE_HOME=/root/.cache; "
        "export XDG_STATE_HOME=/root/.local/state; "
        "mkdir -p /root/.codex /root/.claude /root/.cache /root/.local/state; "
        "echo '[ctf-harness] container user:'; id; "
        "echo '[ctf-harness] Codex auth env:'; "
        "env | grep -E '^(OPENAI_API_KEY|CODEX_ACCESS_TOKEN)=' | sed 's/=.*/=<set>/' || true; "
        "if ! command -v codex >/dev/null 2>&1; then "
        "echo '[ctf-harness] codex CLI not found in ctf-ai-solver image; rebuild the tools image from the dashboard.'; "
        "echo '[ctf-harness] globally installed npm packages:'; "
        "npm list -g --depth=0 2>/dev/null || true; "
        "exit 127; "
        "fi; "
        "echo '[ctf-harness] codex CLI:'; command -v codex; codex --version 2>&1 || true; "
        f"echo '[ctf-harness] codex model: {shlex.quote(codex_model())}'; "
        "if [ -f /root/.codex/auth.json ]; then "
        "echo '[ctf-harness] host codex auth.json mounted'; "
        "unset CODEX_ACCESS_TOKEN; "
        "fi; "
        "if codex login status >/dev/null 2>&1; then "
        "echo '[ctf-harness] codex auth status: logged in'; "
        "unset CODEX_ACCESS_TOKEN; "
        "elif [ -n \"${CODEX_ACCESS_TOKEN:-}\" ] && [ -z \"${OPENAI_API_KEY:-}\" ]; then "
        "echo '[ctf-harness] codex oauth login start'; "
        "timeout 30s sh -lc 'printenv CODEX_ACCESS_TOKEN | codex login --with-access-token' 2>&1; "
        "login_status=$?; "
        "if [ \"$login_status\" -ne 0 ]; then "
        "echo \"[ctf-harness] codex oauth login failed with code $login_status\"; "
        "exit \"$login_status\"; "
        "fi; "
        "echo '[ctf-harness] codex oauth login succeeded'; "
        "unset CODEX_ACCESS_TOKEN; "
        "else "
        "echo '[ctf-harness] codex auth status failed and no usable CODEX_ACCESS_TOKEN/OPENAI_API_KEY was provided'; "
        "codex login status 2>&1 || true; "
        "exit 1; "
        "fi; "
        "echo '[ctf-harness] codex exec start'; "
        "prompt_file="
        f"{shlex.quote(prompt_path)}; "
        "if [ "
        f"{shlex.quote(action)} = continue"
        " ]; then "
        "if [ -d /root/.codex/sessions ] && find /root/.codex/sessions -type f | grep -q .; then "
        "echo '[ctf-harness] codex resuming previous exec session'; "
        f"exec {resume_exec} \"$(cat \"$prompt_file\")\" </dev/null; "
        "else "
        "echo '[ctf-harness] no prior Codex session found; starting a fresh exec session'; "
        f"exec {fresh_exec} \"$(cat \"$prompt_file\")\" </dev/null; "
        "fi; "
        "else "
        f"exec {fresh_exec} \"$(cat \"$prompt_file\")\" </dev/null; "
        "fi"
    )
    return ["sh", "-lc", shell_script]


def kiro_inner_command(action: str, prompt_path: str = f"/workspace/{PROMPT_FILENAME}") -> list[str]:
    # Kiro CLI (Amazon) is Bedrock-backed via AWS SSO / bearer tokens.
    # We copy the host's ~/.kiro and ~/.aws into the container so the CLI can use
    # cached SSO tokens or the configured AWS profile. Prompt is passed as the
    # positional INPUT arg (kiro-cli chat reads INPUT from argv, not stdin).
    model = kiro_model()
    kiro_args = ["kiro-cli", "chat", "--no-interactive", "--trust-all-tools"]
    if action == "continue":
        kiro_args.append("--resume")
    if model:
        kiro_args.extend(["--model", model])
    base_command = " ".join(shlex.quote(part) for part in kiro_args)
    shell_script = (
        "export HOME=/root; "
        "export XDG_CACHE_HOME=/root/.cache; "
        "export XDG_STATE_HOME=/root/.local/state; "
        "mkdir -p /root/.kiro /root/.aws /root/.cache /root/.local/state; "
        "echo '[ctf-harness] container user:'; id; "
        "echo '[ctf-harness] Kiro auth env:'; "
        "env | grep -E '^(KIRO_API_KEY|AWS_BEARER_TOKEN_BEDROCK|AWS_PROFILE|AWS_REGION|AWS_DEFAULT_REGION)=' | sed 's/=.*/=<set>/' || true; "
        "if ! command -v kiro-cli >/dev/null 2>&1; then "
        "echo '[ctf-harness] kiro-cli not found in ctf-ai-solver image; rebuild the tools image so the Kiro installer runs.'; "
        "exit 127; "
        "fi; "
        "echo '[ctf-harness] kiro-cli:'; command -v kiro-cli; kiro-cli --version 2>&1 || true; "
        f"echo '[ctf-harness] kiro model: {shlex.quote(model)}'; "
        "if [ -f /root/.kiro/secrets.json ]; then echo '[ctf-harness] host kiro secrets.json mounted'; fi; "
        "if [ -d /root/.aws/sso/cache ]; then echo '[ctf-harness] host AWS SSO cache mounted'; fi; "
        f"exec {base_command} \"$(cat {shlex.quote(prompt_path)})\" </dev/null"
    )
    return ["sh", "-lc", shell_script]


def opencode_inner_command(action: str, prompt_path: str = f"/workspace/{PROMPT_FILENAME}") -> list[str]:
    # OpenCode (sst/opencode) supports non-interactive runs via `opencode run <prompt>`.
    # Auth precedence in the container: mounted ~/.local/share/opencode/auth.json,
    # then provider API keys (ANTHROPIC_API_KEY / OPENAI_API_KEY / OPENCODE_API_KEY).
    model = opencode_model()
    opencode_args = ["opencode", "run"]
    if model:
        opencode_args.extend(["--model", model])
    if action == "continue":
        opencode_args.append("--continue")
    base_command = " ".join(shlex.quote(part) for part in opencode_args)
    shell_script = (
        "export HOME=/root; "
        "export XDG_CACHE_HOME=/root/.cache; "
        "export XDG_STATE_HOME=/root/.local/state; "
        "export XDG_DATA_HOME=/root/.local/share; "
        "export XDG_CONFIG_HOME=/root/.config; "
        "mkdir -p /root/.local/share/opencode /root/.config/opencode /root/.cache /root/.local/state; "
        "echo '[ctf-harness] container user:'; id; "
        "echo '[ctf-harness] OpenCode auth env:'; "
        "env | grep -E '^(OPENCODE_API_KEY|OPENCODE_AUTH_TOKEN|ANTHROPIC_API_KEY|OPENAI_API_KEY)=' | sed 's/=.*/=<set>/' || true; "
        "if ! command -v opencode >/dev/null 2>&1; then "
        "echo '[ctf-harness] opencode CLI not found in ctf-ai-solver image; rebuild the tools image (opencode is installed via npm at build time).'; "
        "echo '[ctf-harness] globally installed npm packages:'; "
        "npm list -g --depth=0 2>/dev/null || true; "
        "exit 127; "
        "fi; "
        "echo '[ctf-harness] opencode:'; command -v opencode; opencode --version 2>&1 || true; "
        f"echo '[ctf-harness] opencode model: {shlex.quote(model)}'; "
        "if [ -f /root/.local/share/opencode/auth.json ]; then "
        "echo '[ctf-harness] host opencode auth.json mounted'; "
        "fi; "
        f"exec {base_command} \"$(cat {shlex.quote(prompt_path)})\" </dev/null"
    )
    return ["sh", "-lc", shell_script]


def _copy_aws_toolkit(home: Path) -> None:
    """Mirror the host's AWS setup (credentials + config + SSO cache) into the
    container's home so `aws --profile ...`, boto3, and Bedrock CLIs all work
    the same way inside the container as they do on the host.

    Called for EVERY agent (not just kiro/opencode) because a CTF challenge
    may need AWS access regardless of which agent is driving.

    Does NOT copy the IAM key pool file — the pool contains all 23 secrets
    but only one key should ever land in a container (see iam_pool_env_args).
    Also does NOT force-copy if the target already exists (agent-specific
    branches earlier in docker_command may have populated it).
    """
    aws_target = home / ".aws"
    aws_target.mkdir(parents=True, exist_ok=True)
    for aws_file in ("config", "credentials"):
        source = host_aws_dir() / aws_file
        target = aws_target / aws_file
        if source.exists() and not target.exists():
            shutil.copy2(source, target)
    aws_sso_cache = host_aws_dir() / "sso" / "cache"
    if aws_sso_cache.exists():
        target_cache = aws_target / "sso" / "cache"
        target_cache.mkdir(parents=True, exist_ok=True)
        for entry in aws_sso_cache.iterdir():
            target_file = target_cache / entry.name
            if entry.is_file() and not target_file.exists():
                shutil.copy2(entry, target_file)


def docker_command(challenge_dir: Path, inner_command: list[str], image: str = DEFAULT_CTF_IMAGE, agent: str = "agent") -> list[str]:
    challenge_dir = challenge_dir.resolve()
    home = challenge_dir / ".agent-home"
    home.mkdir(parents=True, exist_ok=True)
    for directory in (
        home / ".claude",
        home / ".codex",
        home / ".kiro",
        home / ".aws",
        home / ".local" / "share" / "kiro-cli",
        home / ".local" / "share" / "opencode",
        home / ".config" / "opencode",
        home / ".cache",
        home / ".local" / "state",
    ):
        directory.mkdir(parents=True, exist_ok=True)
    if agent == "claude" and host_claude_credentials_path().exists():
        shutil.copy2(host_claude_credentials_path(), home / ".claude" / ".credentials.json")
    if agent == "codex" and host_codex_auth_path().exists():
        shutil.copy2(host_codex_auth_path(), home / ".codex" / "auth.json")
    if agent == "codex":
        write_codex_mcp_config(home / ".codex")
    if agent == "kiro":
        # The REAL Kiro CLI auth store is data.sqlite3 (auth_kv table). Files in
        # ~/.kiro/ (secrets.json, argv.json) hold only MCP client creds and are
        # NOT sufficient for chat — mounting data.sqlite3 is what makes container
        # kiro-cli inherit the host's logged-in identity.
        kiro_share_target = home / ".local" / "share" / "kiro-cli"
        kiro_share_target.mkdir(parents=True, exist_ok=True)
        host_kiro_sqlite = host_kiro_data_sqlite_path()
        if host_kiro_sqlite.exists():
            shutil.copy2(host_kiro_sqlite, kiro_share_target / "data.sqlite3")
        # Copy top-level ~/.kiro files.
        for name in ("secrets.json", "argv.json", ".trust-migration.json"):
            source = host_kiro_config_dir() / name
            if source.exists():
                shutil.copy2(source, home / ".kiro" / name)
        # Copy ~/.kiro subdirs that hold agent definitions and settings.
        # Skip logs/sessions/session-index (ephemeral, large) and skills/steering/powers
        # (they're often OneDrive-symlinked reparse points on Bryan's setup, cause
        # WinError 3 during copytree, and aren't needed for container-side chat).
        kiro_subdirs_to_copy = ("agents", "settings", "extensions", "tasks")
        for subdir in kiro_subdirs_to_copy:
            source_dir = host_kiro_config_dir() / subdir
            if not source_dir.exists() or not source_dir.is_dir():
                continue
            target_dir = home / ".kiro" / subdir
            if target_dir.exists():
                shutil.rmtree(target_dir)
            try:
                shutil.copytree(source_dir, target_dir, ignore_dangling_symlinks=True)
            except shutil.Error:
                # Best-effort: partial copy is fine; container-side kiro-cli will
                # fall back to its baked-in defaults for any missing pieces.
                pass
        # AWS SSO cache (for the plugin fallback path); Kiro's own token lives
        # in data.sqlite3 above, but if the plugin also asks AWS SDK for creds
        # it needs these.
        aws_sso_cache = host_aws_dir() / "sso" / "cache"
        if aws_sso_cache.exists():
            target_cache = home / ".aws" / "sso" / "cache"
            target_cache.mkdir(parents=True, exist_ok=True)
            for entry in aws_sso_cache.iterdir():
                if entry.is_file():
                    shutil.copy2(entry, target_cache / entry.name)
        for aws_file in ("config", "credentials"):
            source = host_aws_dir() / aws_file
            if source.exists():
                shutil.copy2(source, home / ".aws" / aws_file)
    if agent == "opencode":
        opencode_share_target = home / ".local" / "share" / "opencode"
        for name in ("auth.json", "account.json", "mcp-auth.json"):
            source = host_opencode_share_dir() / name
            if source.exists():
                shutil.copy2(source, opencode_share_target / name)
        opencode_config_source = host_opencode_config_dir()
        if opencode_config_source.exists():
            opencode_config_target = home / ".config" / "opencode"
            for entry in opencode_config_source.iterdir():
                target = opencode_config_target / entry.name
                if entry.is_file():
                    shutil.copy2(entry, target)
                elif entry.is_dir():
                    if target.exists():
                        shutil.rmtree(target)
                    shutil.copytree(entry, target)
    # Always mirror the host's AWS toolkit (creds + config + SSO cache) into
    # every per-challenge container home. Runs LAST so agent-specific branches
    # above (kiro's targeted AWS copy) get first shot; this is the fallback for
    # any files those branches didn't touch.
    _copy_aws_toolkit(home)
    name = f"ctf-{challenge_dir.name[:48]}-{agent}-{int(time.time())}"
    command = [
        "docker",
        "run",
        "--rm",
        "--user",
        "0:0",
        "--name",
        name,
        "--label",
        "com.docker.compose.project=ctfsolver",
        "--network",
        "host",
        "--cap-add",
        "SYS_PTRACE",
        "--security-opt",
        "seccomp=unconfined",
        "-v",
        f"{challenge_dir}:/workspace:Z",
        "-v",
        f"{home}:/root:Z",
        "-w",
        "/workspace",
        "-e",
        "HOME=/root",
    ]
    command.extend(docker_env_args(agent))
    # Overlay a pool-selected IAM key for Bedrock-backed agents so concurrent
    # containers spread across different identities. Last-write-wins on -e in
    # docker run, so this correctly overrides any host AWS_ACCESS_KEY_ID that
    # docker_env_args might have forwarded.
    pool_args, picked = iam_pool_env_args(challenge_dir.name, agent)
    if pool_args:
        command.extend(pool_args)
        # Log which key was picked so debugging is easier (secret not logged).
        (home / ".ctf-harness-iam-key.txt").write_text(
            f"agent={agent}\nlabel={picked.label}\narn={picked.arn}\naccount={picked.account}\n"
            f"key_id={picked.access_key_id}\n",
            encoding="utf-8",
        )
    command.append(image)
    command.extend(inner_command)
    return command


def run_streaming_agent(
    challenge_dir: Path,
    agent: str,
    action: str,
    prompt: str,
    command: list[str],
    env_summary: str,
    log_filename: str,
    last_filename: str,
) -> int:
    """Run the containerised agent, streaming its stdout to log + last-message files.

    Portable across Windows and POSIX. Uses a background thread reading
    subprocess.stdout in blocking mode into a queue; the main loop drains the
    queue with a short timeout so we can still interleave heartbeat / no-output
    notices without blocking indefinitely. (The earlier selector-based
    implementation used selectors.DefaultSelector which on Windows only accepts
    socket handles — subprocess pipes raised WinError 10038.)
    """
    import queue as _queue
    import threading as _threading

    challenge = load_challenge(challenge_dir)
    log_path = challenge_dir / log_filename
    last_path = challenge_dir / last_filename
    prompt_path = challenge_dir / PROMPT_FILENAME
    prompt_path.write_text(prompt, encoding="utf-8")
    prompt_path.chmod(0o644)
    masked_command = mask_command(command)
    run_id = record_run_start(challenge_dir, challenge, agent, action, masked_command, log_path, last_path)
    printable = " ".join(subprocess.list2cmdline([part]) for part in masked_command)
    output = bytearray()
    returncode = 1

    def _reader(pipe, q: "_queue.Queue[bytes | None]") -> None:
        """Blocking read loop on the child's stdout, pushing chunks to a queue.
        Pushes None as EOF sentinel so the drain loop knows the child closed stdout."""
        try:
            while True:
                chunk = pipe.read1(8192) if hasattr(pipe, "read1") else pipe.read(8192)
                if not chunk:
                    break
                q.put(chunk)
        finally:
            q.put(None)

    with log_path.open("ab") as log:
        log.write(f"\n\n=== {time.strftime('%Y-%m-%d %H:%M:%S')} ===\n".encode())
        log.write(f"[ctf-harness] {env_summary}\n".encode())
        log.write(f"$ {printable}\n\n".encode())
        log.flush()

        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        assert process.stdout is not None
        chunk_queue: "_queue.Queue[bytes | None]" = _queue.Queue()
        reader_thread = _threading.Thread(
            target=_reader, args=(process.stdout, chunk_queue), daemon=True
        )
        reader_thread.start()

        next_heartbeat = time.monotonic() + 5
        next_no_output_notice = time.monotonic() + NO_OUTPUT_NOTICE_SECONDS
        last_output_at = time.monotonic()
        eof_seen = False
        while True:
            now = time.monotonic()
            if now >= next_heartbeat:
                record_run_heartbeat(challenge_dir, run_id)
                next_heartbeat = now + 5
            if now >= next_no_output_notice:
                quiet_for = int(now - last_output_at)
                notice = f"\n[ctf-harness] {agent} still running; no output for {quiet_for}s.\n".encode()
                log.write(notice)
                log.flush()
                output.extend(notice)
                if len(output) > OUTPUT_BUFFER_LIMIT:
                    del output[: len(output) - OUTPUT_BUFFER_LIMIT]
                last_path.write_bytes(output[-20000:])
                next_no_output_notice = now + NO_OUTPUT_NOTICE_SECONDS

            try:
                chunk = chunk_queue.get(timeout=0.5)
            except Exception:
                chunk = None
                # Timeout — no chunk this iteration. Fall through to poll below.
                if not eof_seen and process.poll() is not None:
                    # Process exited but reader thread may still have queued data;
                    # drain briefly before breaking.
                    reader_thread.join(timeout=1.0)
                    continue
                if eof_seen and process.poll() is not None:
                    break
                continue

            if chunk is None:
                # EOF sentinel from reader thread
                eof_seen = True
                if process.poll() is not None:
                    break
                continue

            last_output_at = time.monotonic()
            next_no_output_notice = last_output_at + NO_OUTPUT_NOTICE_SECONDS
            output.extend(chunk)
            if len(output) > OUTPUT_BUFFER_LIMIT:
                del output[: len(output) - OUTPUT_BUFFER_LIMIT]
            log.write(chunk)
            log.flush()
            last_path.write_bytes(output[-20000:])

        returncode = process.wait()
        reader_thread.join(timeout=2.0)

        reported_error, error_message = stream_reported_error(bytes(output))
        if returncode == 0 and reported_error:
            returncode = 1
            warning = f"\n[ctf-harness] {agent} stream reported an error: {error_message}\n".encode()
            log.write(warning)
            log.flush()
            output.extend(warning)
        if not last_path.exists() or agent != "codex":
            last_path.write_bytes(bytes(output[-20000:]))
        if returncode == 0 and not bytes(output).strip():
            warning = f"\n[ctf-harness] {agent} exited with code 0 but produced no output.\n".encode()
            log.write(warning)
            last_path.write_bytes(warning)
    record_run_finish(challenge_dir, run_id, returncode, log_path, last_path)
    return returncode


def prompt_for_action(challenge_dir: Path, action: str, message: str) -> str:
    challenge = load_challenge(challenge_dir)
    prompt = (challenge_dir / "PROMPT.md").read_text(encoding="utf-8")
    if action == "continue":
        prompt = build_followup_prompt(challenge, message, challenge_dir=challenge_dir)
    return prompt


def run_claude(challenge_dir: Path, action: str, message: str = "") -> int:
    load_dotenv()
    prepare_claude_auth_env()
    if not has_claude_auth():
        raise HarnessError(
            "Claude auth is not configured. Set ANTHROPIC_API_KEY or ANTHROPIC_AUTH_TOKEN "
            "in .env, or sign in with Claude Code so ~/.claude/.credentials.json exists, then rerun."
        )
    prompt = prompt_for_action(challenge_dir, action, message)
    command = docker_command(challenge_dir, claude_inner_command(action), agent="claude")
    return run_streaming_agent(challenge_dir, "claude", action, prompt, command, claude_env_summary(), "claude.log", "claude-last-message.txt")


def run_codex(challenge_dir: Path, action: str, message: str = "") -> int:
    load_dotenv()
    if not has_codex_auth():
        raise HarnessError(
            "Codex auth is not configured. Set OPENAI_API_KEY or CODEX_ACCESS_TOKEN in .env, "
            "or sign in with Codex so ~/.codex/auth.json exists, then rerun."
        )
    prompt = prompt_for_action(challenge_dir, action, message)
    command = docker_command(challenge_dir, codex_inner_command(action), agent="codex")
    return run_streaming_agent(challenge_dir, "codex", action, prompt, command, codex_env_summary(), "codex.log", "codex-last-message.txt")


def run_kiro(challenge_dir: Path, action: str, message: str = "") -> int:
    load_dotenv()
    prepare_kiro_auth_env()
    if not has_kiro_auth():
        raise HarnessError(
            "Kiro auth is not configured. Set KIRO_API_KEY, AWS_BEARER_TOKEN_BEDROCK, or AWS_PROFILE "
            "in .env, or sign in with `kiro-cli` so ~/.kiro/secrets.json (and ~/.aws/sso/cache) exist, "
            "then rerun."
        )
    prompt = prompt_for_action(challenge_dir, action, message)
    command = docker_command(challenge_dir, kiro_inner_command(action), agent="kiro")
    return run_streaming_agent(
        challenge_dir, "kiro", action, prompt, command, kiro_env_summary(), "kiro.log", "kiro-last-message.txt"
    )


def run_opencode(challenge_dir: Path, action: str, message: str = "") -> int:
    load_dotenv()
    prepare_opencode_auth_env()
    if not has_opencode_auth():
        raise HarnessError(
            "OpenCode auth is not configured. Set OPENCODE_API_KEY, OPENCODE_AUTH_TOKEN, "
            "ANTHROPIC_API_KEY, or OPENAI_API_KEY in .env, or sign in with `opencode auth login` "
            "so ~/.local/share/opencode/auth.json exists, then rerun."
        )
    prompt = prompt_for_action(challenge_dir, action, message)
    command = docker_command(challenge_dir, opencode_inner_command(action), agent="opencode")
    return run_streaming_agent(
        challenge_dir,
        "opencode",
        action,
        prompt,
        command,
        opencode_env_summary(),
        "opencode.log",
        "opencode-last-message.txt",
    )


# ---------------------------------------------------------------------------
# Agent fallback / auto-resolution
# ---------------------------------------------------------------------------

# Fallback preference order when the caller doesn't specify an agent (or asks
# for one whose auth is unavailable). The harness picks the first available.
# Kiro + OpenCode benefit from the pooled IAM keys; if neither is set up,
# fall back to Claude, then Codex.
AGENT_FALLBACK_ORDER = ("kiro", "opencode", "claude", "codex")


def agent_availability() -> dict[str, bool]:
    """Snapshot of which agents currently have usable auth on this host."""
    return {
        "claude": has_claude_auth(),
        "codex": has_codex_auth(),
        "kiro": has_kiro_auth(),
        "opencode": has_opencode_auth(),
    }


def resolve_available_agent(preferred: str | None = None) -> str:
    """Pick a usable agent, honouring preference when possible.

    Order:
      1. If `preferred` is set and its auth is available, return it.
      2. Otherwise, walk AGENT_FALLBACK_ORDER and return the first available.
      3. If nothing is authed, raise HarnessError with the summary.

    Optional override: CTF_HARNESS_AGENT_FALLBACK_ORDER (comma-separated) lets
    you customise the walk without touching code.
    """
    avail = agent_availability()
    if preferred and avail.get(preferred):
        return preferred
    order_env = os.environ.get("CTF_HARNESS_AGENT_FALLBACK_ORDER", "").strip()
    order = tuple(a.strip() for a in order_env.split(",") if a.strip()) if order_env else AGENT_FALLBACK_ORDER
    for a in order:
        if avail.get(a):
            return a
    raise HarnessError(
        "No agent is authenticated. Set at least one: "
        f"{avail}. See README §3 for auth options."
    )


AGENT_DISPATCH = {
    "claude": run_claude,
    "codex": run_codex,
    "kiro": run_kiro,
    "opencode": run_opencode,
}


def run_auto(challenge_dir: Path, action: str, message: str = "", preferred: str | None = None) -> tuple[str, int]:
    """Dispatch to the best-available agent. Returns (agent_used, returncode)."""
    agent = resolve_available_agent(preferred)
    return agent, AGENT_DISPATCH[agent](challenge_dir, action, message)


# ---------------------------------------------------------------------------
# Container-side runtime fallback: if the chosen agent's container fails
# because the CLI is missing, auth is bad, or the container crashed for
# infrastructure reasons (not the challenge itself being hard), retry with
# the next agent in AGENT_FALLBACK_ORDER.
# ---------------------------------------------------------------------------

# Substrings we look for in the run log to classify a failure as "infra"
# (retriable with a different agent) vs "challenge" (agent tried but couldn't
# solve — different agent unlikely to help, don't blindly retry).
INFRA_FAILURE_SIGNALS = (
    # CLI missing (Dockerfile didn't bake it in, or install failed)
    "kiro-cli not found",
    "codex CLI not found",
    "opencode CLI not found",
    "command not found",
    "not found in ctf-ai-solver image",
    "exec: \"claude\": executable file not found",
    "exec: \"codex\": executable file not found",
    "exec: \"opencode\": executable file not found",
    "exec: \"kiro-cli\": executable file not found",
    # Auth failures we know can be caused by env misconfig, not challenge difficulty
    "InvalidClientTokenId",
    "The security token included in the request is invalid",
    "The security token included in the request is expired",
    "codex auth status failed and no usable",
    "Kiro auth is not configured",
    "OpenCode auth is not configured",
    "Claude auth is not configured",
    "Codex auth is not configured",
    "no Kiro auth is configured",
    "no OpenCode auth is configured",
    # SSO / Bedrock plugin failures
    "Session token not found or invalid",
    "UnauthorizedException",
    # Container itself couldn't start
    "docker: Error response from daemon",
)


def _log_indicates_infra_failure(challenge_dir: Path, agent: str) -> tuple[bool, str]:
    """Read the tail of the just-finished run log and check for infra-failure
    signals. Returns (is_infra_failure, matched_signal)."""
    log_candidates = [
        challenge_dir / f"{agent}.log",
        challenge_dir / f"{agent}-last-message.txt",
    ]
    for log_path in log_candidates:
        if not log_path.exists():
            continue
        try:
            # Read the last 32KB — enough to see the failure surface
            data = log_path.read_bytes()
            tail = data[-32_768:].decode("utf-8", errors="replace")
        except Exception:
            continue
        for signal in INFRA_FAILURE_SIGNALS:
            if signal in tail:
                return True, signal
    return False, ""


def run_auto_with_fallback(
    challenge_dir: Path,
    action: str,
    message: str = "",
    preferred: str | None = None,
    max_agents: int = 3,
) -> tuple[str, int, list[tuple[str, int, str]]]:
    """Run the best-available agent; if it fails due to an infrastructure
    signal (CLI missing, auth broken, session expired), retry with the next
    available agent in AGENT_FALLBACK_ORDER. Bounded by max_agents (default 3)
    to avoid burning excessive container time on repeat runs.

    Returns (final_agent, final_returncode, attempts) where attempts is a list
    of (agent, returncode, reason) tuples describing what happened.

    Does NOT retry on non-infra failures — if an agent runs the challenge and
    exits with rc=1 because the challenge is hard, that's a signal the harness
    should surface (agent tried), not a signal to burn another agent's time.
    """
    load_dotenv()
    avail = agent_availability()
    order_env = os.environ.get("CTF_HARNESS_AGENT_FALLBACK_ORDER", "").strip()
    order = tuple(a.strip() for a in order_env.split(",") if a.strip()) if order_env else AGENT_FALLBACK_ORDER
    if preferred and preferred in order:
        # Move preferred to front so it goes first
        order = (preferred,) + tuple(a for a in order if a != preferred)
    elif preferred and avail.get(preferred):
        order = (preferred,) + order

    attempts: list[tuple[str, int, str]] = []
    for agent in order:
        if len(attempts) >= max_agents:
            break
        if not avail.get(agent):
            attempts.append((agent, -1, "unavailable (no auth)"))
            continue
        try:
            rc = AGENT_DISPATCH[agent](challenge_dir, action, message)
        except HarnessError as e:
            attempts.append((agent, -1, f"HarnessError: {e}"))
            continue
        if rc == 0:
            attempts.append((agent, rc, "success"))
            return agent, rc, attempts
        # Non-zero — classify
        is_infra, signal = _log_indicates_infra_failure(challenge_dir, agent)
        if is_infra:
            attempts.append((agent, rc, f"infra: {signal!r}"))
            continue
        # Non-infra failure — the agent tried, don't retry with another
        attempts.append((agent, rc, "agent tried but did not solve; not retrying"))
        return agent, rc, attempts

    return (attempts[-1][0] if attempts else ""), (attempts[-1][1] if attempts else -1), attempts


def run_batch(
    challenge_dirs: list[Path],
    action: str = "start",
    message: str = "",
    preferred: str | None = None,
    max_concurrent: int | None = None,
) -> list[tuple[Path, str, int, str]]:
    """Solve multiple challenges in parallel, each with its own container.

    Uses a thread pool bounded by max_concurrent (env-configurable via
    CTFTOOLKIT_MAX_CONCURRENT_AGENTS, default 4). Each challenge:
      1. resolves its own agent via fallback hierarchy,
      2. draws a distinct IAM key from the pool (deterministic via slug),
      3. spawns its container and runs to completion.

    Returns list of (challenge_dir, agent_used, returncode, err_or_empty).
    """
    import concurrent.futures as cf

    if max_concurrent is None:
        try:
            max_concurrent = int(os.environ.get("CTFTOOLKIT_MAX_CONCURRENT_AGENTS", "4"))
        except ValueError:
            max_concurrent = 4
    max_concurrent = max(1, max_concurrent)

    results: list[tuple[Path, str, int, str]] = []

    def _one(cd: Path) -> tuple[Path, str, int, str]:
        try:
            agent, rc = run_auto(cd, action=action, message=message, preferred=preferred)
            return (cd, agent, rc, "")
        except Exception as exc:  # noqa: BLE001 - surface per-challenge failure
            return (cd, "", -1, f"{type(exc).__name__}: {exc}")

    with cf.ThreadPoolExecutor(max_workers=max_concurrent) as pool:
        futures = {pool.submit(_one, cd): cd for cd in challenge_dirs}
        for fut in cf.as_completed(futures):
            results.append(fut.result())
    # Preserve input order for callers
    order = {cd: i for i, cd in enumerate(challenge_dirs)}
    results.sort(key=lambda r: order.get(r[0], 1_000_000))
    return results
