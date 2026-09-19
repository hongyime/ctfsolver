from __future__ import annotations

import json
import os
import selectors
import shlex
import shutil
import subprocess
import time
from pathlib import Path

from .config import DEFAULT_CODEX_MODEL, DEFAULT_CTF_IMAGE, DEFAULT_DOCKERFILE, DEFAULT_KIRO_MODEL, DEFAULT_OPENCODE_MODEL, load_dotenv
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
    if host_kiro_secrets_path().exists():
        return "host Kiro secrets.json is available"
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
            or env_name in {"AWS_BEARER_TOKEN_BEDROCK", "AWS_PROFILE", "AWS_REGION", "AWS_DEFAULT_REGION"}
        ):
            continue
        if prefer_host_codex_auth and env_name == "CODEX_ACCESS_TOKEN":
            continue
        value = os.environ.get(env_name)
        if value:
            args.extend(["-e", f"{env_name}={value}"])
    return args


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
    # cached SSO tokens or the configured AWS profile. Prompt goes through stdin
    # so we don't struggle with shell quoting of multi-line CTF prompts.
    model = kiro_model()
    kiro_args = ["kiro-cli", "chat", "--no-interactive", "--trust-all-tools"]
    if model:
        kiro_args.extend(["--model", model])
    base_command = " ".join(shlex.quote(part) for part in kiro_args)
    resume_note = "(action=continue: fresh Kiro session; Kiro does not expose --resume in CLI mode)" if action == "continue" else ""
    shell_script = (
        "export HOME=/root; "
        "export XDG_CACHE_HOME=/root/.cache; "
        "export XDG_STATE_HOME=/root/.local/state; "
        "mkdir -p /root/.kiro /root/.aws /root/.cache /root/.local/state; "
        "echo '[ctf-harness] container user:'; id; "
        "echo '[ctf-harness] Kiro auth env:'; "
        "env | grep -E '^(KIRO_API_KEY|AWS_BEARER_TOKEN_BEDROCK|AWS_PROFILE|AWS_REGION|AWS_DEFAULT_REGION)=' | sed 's/=.*/=<set>/' || true; "
        "if ! command -v kiro-cli >/dev/null 2>&1; then "
        "echo '[ctf-harness] kiro-cli not found in ctf-ai-solver image; rebuild the tools image with the Kiro CLI install step, or install kiro-cli manually inside the container.'; "
        "exit 127; "
        "fi; "
        "echo '[ctf-harness] kiro-cli:'; command -v kiro-cli; kiro-cli --version 2>&1 || true; "
        f"echo '[ctf-harness] kiro model: {shlex.quote(model)}'; "
        f"echo {shlex.quote('[ctf-harness] ' + resume_note) if resume_note else 'true'}; "
        f"exec {base_command} < {shlex.quote(prompt_path)}"
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


def docker_command(challenge_dir: Path, inner_command: list[str], image: str = DEFAULT_CTF_IMAGE, agent: str = "agent") -> list[str]:
    challenge_dir = challenge_dir.resolve()
    home = challenge_dir / ".agent-home"
    home.mkdir(parents=True, exist_ok=True)
    for directory in (
        home / ".claude",
        home / ".codex",
        home / ".kiro",
        home / ".aws",
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
        # Kiro secrets.json + argv.json + SSO cache. Only files we know are safe to copy.
        for name in ("secrets.json", "argv.json"):
            source = host_kiro_config_dir() / name
            if source.exists():
                shutil.copy2(source, home / ".kiro" / name)
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
    with log_path.open("ab") as log:
        log.write(f"\n\n=== {time.strftime('%Y-%m-%d %H:%M:%S')} ===\n".encode())
        log.write(f"[ctf-harness] {env_summary}\n".encode())
        log.write(f"$ {printable}\n\n".encode())
        log.flush()
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        next_heartbeat = time.monotonic() + 5
        next_no_output_notice = time.monotonic() + NO_OUTPUT_NOTICE_SECONDS
        last_output_at = time.monotonic()
        assert process.stdout is not None
        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ)
        while True:
            if time.monotonic() >= next_heartbeat:
                record_run_heartbeat(challenge_dir, run_id)
                next_heartbeat = time.monotonic() + 5
            if time.monotonic() >= next_no_output_notice:
                quiet_for = int(time.monotonic() - last_output_at)
                notice = f"\n[ctf-harness] {agent} still running; no output for {quiet_for}s.\n".encode()
                log.write(notice)
                log.flush()
                output.extend(notice)
                if len(output) > OUTPUT_BUFFER_LIMIT:
                    del output[: len(output) - OUTPUT_BUFFER_LIMIT]
                last_path.write_bytes(output[-20000:])
                next_no_output_notice = time.monotonic() + NO_OUTPUT_NOTICE_SECONDS
            for key, _ in selector.select(timeout=0.5):
                chunk = key.fileobj.read1(8192)
                if chunk:
                    last_output_at = time.monotonic()
                    next_no_output_notice = last_output_at + NO_OUTPUT_NOTICE_SECONDS
                    output.extend(chunk)
                    if len(output) > OUTPUT_BUFFER_LIMIT:
                        del output[: len(output) - OUTPUT_BUFFER_LIMIT]
                    log.write(chunk)
                    log.flush()
                    last_path.write_bytes(output[-20000:])
            returncode = process.poll()
            if returncode is not None:
                break
        selector.close()
        remainder = process.stdout.read()
        if remainder:
            output.extend(remainder)
            if len(output) > OUTPUT_BUFFER_LIMIT:
                del output[: len(output) - OUTPUT_BUFFER_LIMIT]
            log.write(remainder)
            log.flush()
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
        prompt = build_followup_prompt(challenge, message)
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
