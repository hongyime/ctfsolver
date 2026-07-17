from __future__ import annotations

import os
import html
import sys
import concurrent.futures
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "src"))
from typing import Any

import streamlit as st

from ctf_harness_app.agents import (
    build_tools_image,
    claude_env_summary,
    codex_env_summary,
    has_claude_auth,
    has_codex_auth,
    run_claude,
    run_codex,
)
from ctf_harness_app.agents import prepare_claude_auth_env, prepare_codex_auth_env
from ctf_harness_app.config import DEFAULT_OUTPUT_DIR, load_dotenv
from ctf_harness_app.ctfd import CTFdClient
from ctf_harness_app.toolkit import toolkit_status_snapshot
from ctf_harness_app.workspace import (
    collect_dashboard,
    download_challenges,
    load_harness_state,
    mark_agent_succeeded,
    refresh_solved_from_ctfd,
    resolve_challenge_dir,
    stop_running_agent,
    update_harness_state,
)


load_dotenv()

REFRESH_INTERVAL = "5s"
LAST_MESSAGE_HEIGHT = 360
LOG_TAIL_HEIGHT = 520
ACTIVITY_HEIGHT = 620
ACTIVITY_RENDER_LIMIT = 40
DEFAULT_RAW_LOG_LIMIT = 4_000
DETAIL_VIEWS = ["Runs", "Claude activity", "Claude last", "Claude raw", "Codex activity", "Codex last", "Codex raw"]
RAW_LOG_LIMIT_OPTIONS = {
    "4 KB": 4_000,
    "12 KB": 12_000,
    "50 KB": 50_000,
    "200 KB": 200_000,
}


def apply_styles() -> None:
    st.markdown(
        """
        <style>
        .block-container { padding-top: 1.5rem; }
        div[data-testid="stMetric"] {
            border: 1px solid #30363d;
            border-radius: 8px;
            padding: 0.75rem 0.9rem;
            background: #0d1117;
        }
        .ctf-panel {
            border: 1px solid #30363d;
            border-radius: 8px;
            padding: 1rem 1.1rem;
            margin: 0.75rem 0 0.9rem;
            background: #0d1117;
        }
        .ctf-title {
            font-size: 1.2rem;
            font-weight: 700;
            margin-bottom: 0.35rem;
        }
        .ctf-muted {
            color: #8b949e;
            font-size: 0.85rem;
        }
        .ctf-chip {
            display: inline-block;
            border-radius: 999px;
            padding: 0.16rem 0.55rem;
            margin: 0.18rem 0.25rem 0.18rem 0;
            font-size: 0.78rem;
            font-weight: 650;
            border: 1px solid #30363d;
            background: #161b22;
            color: #c9d1d9;
        }
        .ctf-chip-green { border-color: #238636; color: #7ee787; background: #0f2419; }
        .ctf-chip-blue { border-color: #1f6feb; color: #79c0ff; background: #0d1d33; }
        .ctf-chip-red { border-color: #da3633; color: #ff7b72; background: #2d1517; }
        .ctf-chip-yellow { border-color: #9e6a03; color: #e3b341; background: #2b2111; }
        .ctf-chip-gray { color: #8b949e; }
        </style>
        """,
        unsafe_allow_html=True,
    )


def output_dir() -> Path:
    return Path(st.session_state.get("output_dir", DEFAULT_OUTPUT_DIR))


def raw_log_limit() -> int:
    return int(st.session_state.get("raw_log_limit", DEFAULT_RAW_LOG_LIMIT))


def detail_slugs() -> set[str]:
    return set(st.session_state.get("detail_slugs", []))


def set_detail_slug(slug: str, enabled: bool) -> None:
    slugs = detail_slugs()
    if enabled:
        slugs.add(slug)
    else:
        slugs.discard(slug)
    st.session_state["detail_slugs"] = sorted(slugs)


def detail_views() -> dict[str, str]:
    value = st.session_state.get("detail_views", {})
    return value if isinstance(value, dict) else {}


def set_detail_view(slug: str, view: str) -> None:
    views = detail_views().copy()
    views[slug] = view
    st.session_state["detail_views"] = views


@st.cache_resource
def get_executor() -> concurrent.futures.ThreadPoolExecutor:
    return concurrent.futures.ThreadPoolExecutor(max_workers=10, thread_name_prefix="ctf-harness")


def run_background(name: str, fn: Any, *args: Any, **kwargs: Any) -> None:
    out = output_dir()

    def wrapped() -> None:
        update_harness_state(out, operation=name, operation_status="running", operation_error=None)
        try:
            result = fn(*args, **kwargs)
            if isinstance(result, int) or result is None:
                operation_returncode = result
            elif isinstance(result, (set, list, tuple, dict)):
                operation_returncode = len(result)
            else:
                operation_returncode = str(result)
            operation_status = "failed" if isinstance(result, int) and result != 0 else "succeeded"
            update_harness_state(
                out,
                operation=name,
                operation_status=operation_status,
                operation_returncode=operation_returncode,
                operation_error=None,
            )
        except Exception as exc:
            update_harness_state(out, operation=name, operation_status="failed", operation_error=str(exc))

    get_executor().submit(wrapped)


def status_label(challenge: dict[str, Any]) -> str:
    if challenge.get("solved"):
        return "Solved in CTFd"
    if challenge.get("status") == "running":
        return "Agent running"
    if challenge.get("status") == "stopped":
        return "Agent stopped"
    return "Unsolved in CTFd"


def status_icon(challenge: dict[str, Any]) -> str:
    if challenge.get("solved"):
        return "✅"
    if challenge.get("status") == "running":
        return "▶"
    if challenge.get("status") == "failed":
        return "⚠"
    if challenge.get("status") == "stopped":
        return "■"
    return "○"


def agent_status_tone(status: str | None) -> str:
    return {
        "running": "blue",
        "succeeded": "green",
        "failed": "red",
        "stopped": "yellow",
    }.get(str(status or ""), "gray")


def chip(label: str, tone: str = "gray") -> str:
    return f'<span class="ctf-chip ctf-chip-{tone}">{html.escape(label)}</span>'


def grouped(challenges: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    groups: dict[str, list[dict[str, Any]]] = {}
    for challenge in challenges:
        groups.setdefault(str(challenge.get("category") or "unknown"), []).append(challenge)
    return groups


def render_sidebar(harness: dict[str, Any]) -> None:
    load_dotenv()
    prepare_claude_auth_env()
    prepare_codex_auth_env()
    st.sidebar.header("CTF Harness")
    st.session_state["output_dir"] = st.sidebar.text_input("Workspace", value=st.session_state.get("output_dir", DEFAULT_OUTPUT_DIR))
    ctfd_url = st.sidebar.text_input("CTFd URL", value="https://ctfd.nusgreyhats.org/challenges")

    token_state = "configured" if os.environ.get("CTFD_TOKEN") else "missing"
    claude_state = "configured" if has_claude_auth() else "missing"
    codex_state = "configured" if has_codex_auth() else "missing"
    toolkit_state = toolkit_status_snapshot()
    st.sidebar.markdown(
        " ".join(
            [
                chip(f"CTFd {token_state}", "green" if token_state == "configured" else "red"),
                chip(f"Claude {claude_state}", "green" if claude_state == "configured" else "red"),
                chip(f"Codex {codex_state}", "green" if codex_state == "configured" else "red"),
                chip(
                    f"Toolkit {toolkit_state['state']}",
                    "green" if toolkit_state["ok"] else "yellow",
                ),
            ]
        ),
        unsafe_allow_html=True,
    )
    st.sidebar.caption(
        "Toolkit: "
        f"MCP {toolkit_state['mcp_tools']}, "
        f"registry {toolkit_state['registry_tools'] or 0}, "
        f"skills {toolkit_state['skill_files']}"
    )
    if claude_state == "missing" or codex_state == "missing":
        st.sidebar.caption(
            "Agent auth: "
            f"Claude: {claude_env_summary()}; "
            f"Codex: {codex_env_summary()}. "
            "Sign in with the local CLI or set API keys in .env."
        )
    st.sidebar.divider()
    st.session_state["compact_mode"] = st.sidebar.toggle(
        "Compact mode",
        value=st.session_state.get("compact_mode", True),
        help="Render the challenge list as a lightweight table and open one challenge at a time.",
    )
    raw_log_label = st.sidebar.selectbox(
        "Raw log tail",
        list(RAW_LOG_LIMIT_OPTIONS),
        index=0,
        help="Limits how much raw claude.log text is loaded and rendered per challenge.",
    )
    st.session_state["raw_log_limit"] = RAW_LOG_LIMIT_OPTIONS[raw_log_label]

    st.sidebar.divider()
    st.sidebar.caption("Actions")
    col1, col2 = st.sidebar.columns(2)
    with col1:
        if st.button("Rebuild image", width='stretch'):
            run_background("build-image", build_tools_image)
            st.rerun()
    with col2:
        if st.button("Download", width='stretch'):
            load_dotenv()
            client = CTFdClient(ctfd_url)
            run_background("download", download_challenges, client, output_dir())
            st.rerun()

    if st.sidebar.button("Refresh solved from CTFd", width="stretch"):
        load_dotenv()
        client = CTFdClient(ctfd_url)
        run_background("refresh-solved", refresh_solved_from_ctfd, client, output_dir())
        st.rerun()

    if harness.get("solved_refreshed_at"):
        st.sidebar.caption(f"Solved refreshed: {harness['solved_refreshed_at']}")

    if harness.get("operation"):
        status = harness.get("operation_status") or "unknown"
        message = f"{harness.get('operation')}: {status}"
        if harness.get("operation_error"):
            st.sidebar.error(f"{message}\n\n{harness['operation_error']}")
        elif status == "running":
            st.sidebar.info(message)
        else:
            st.sidebar.success(message)
        if harness.get("operation") == "download":
            done = harness.get("download_done")
            total = harness.get("download_total")
            current = harness.get("download_current")
            if isinstance(done, int) and isinstance(total, int) and total:
                st.sidebar.progress(min(done / total, 1.0), text=f"Download {done}/{total}")
            if current:
                st.sidebar.caption(str(current))


def render_operation_status(harness: dict[str, Any]) -> None:
    if not harness.get("operation"):
        return
    status = harness.get("operation_status") or "unknown"
    message = f"{harness.get('operation')}: {status}"
    if harness.get("operation_error"):
        st.error(f"{message}\n\n{harness['operation_error']}")
    elif status == "running":
        st.info(message)
    else:
        st.success(message)


def render_metrics(challenges: list[dict[str, Any]]) -> None:
    total = len(challenges)
    solved = sum(1 for challenge in challenges if challenge.get("solved"))
    running = sum(1 for challenge in challenges if challenge.get("status") == "running")
    failed = sum(1 for challenge in challenges if challenge.get("status") == "failed" and not challenge.get("solved"))
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Challenges", total)
    col2.metric("Solved", solved)
    col3.metric("Running", running)
    col4.metric("Failed", failed)


def render_log_panel(text: str, *, height: int, wrap: bool = True) -> None:
    white_space = "pre-wrap" if wrap else "pre"
    st.html(
        f"""
        <div style="
          height: {height}px;
          overflow: auto;
          display: flex;
          flex-direction: column-reverse;
          border: 1px solid #30363d;
          border-radius: 6px;
          padding: 0.75rem;
          background: #0d1117;
          color: #e6edf3;
        ">
          <pre style="
            margin: 0;
            white-space: {white_space};
            overflow-wrap: {'anywhere' if wrap else 'normal'};
            font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
            font-size: 0.82rem;
            line-height: 1.35;
            color: #e6edf3;
          ">{html.escape(text)}</pre>
        </div>
        """,
    )


def event_label(kind: str, assistant_label: str = "Claude") -> tuple[str, str]:
    labels = {
        "assistant": (assistant_label, "💬"),
        "tool": ("Tool call", "🔧"),
        "result": ("Tool result", "↩"),
        "error": ("Tool error", "⚠"),
        "session": ("Session", "●"),
        "status": ("Status", "…"),
        "harness": ("Harness", "▣"),
    }
    return labels.get(kind, (kind.title() or "Event", "•"))


def render_activity_events(events: list[dict[str, str]], assistant_label: str = "Claude") -> None:
    if not events:
        st.info(f"No parsed {assistant_label} stream events yet.")
        return
    visible_events = events[-ACTIVITY_RENDER_LIMIT:]
    hidden_count = max(0, len(events) - len(visible_events))
    suffix = f" · showing latest {len(visible_events)}" if hidden_count else f" · {len(events)} events"
    st.caption(f"Newest events first{suffix}")
    if hidden_count:
        st.caption(f"{hidden_count} older events hidden for performance. Use Raw log for the full stream.")
    for event in reversed(visible_events):
        kind = event.get("kind", "event")
        label, icon = event_label(kind, assistant_label)
        title = event.get("title") or label
        body = event.get("body") or ""
        fields = event.get("fields") or {}
        with st.container(border=True):
            cols = st.columns([1, 6])
            cols[0].markdown(f"**{icon} {label}**")
            cols[1].markdown(f"**{title}**")
            if kind == "assistant" and body:
                st.markdown(body)
                continue
            if kind == "tool":
                if fields.get("description"):
                    st.caption(fields["description"])
                if fields.get("command"):
                    st.code(fields["command"].rstrip(), language="bash")
                elif fields.get("input"):
                    st.code(fields["input"].rstrip(), language="json")
                elif body:
                    st.code(body.rstrip(), language="text")
                continue
            if kind in {"result", "error"}:
                if fields.get("command"):
                    st.caption("command")
                    st.code(fields["command"].rstrip(), language="bash")
                if fields.get("stdout"):
                    st.caption("stdout")
                    st.code(fields["stdout"].rstrip(), language="text")
                if fields.get("stderr"):
                    st.caption("stderr")
                    st.code(fields["stderr"].rstrip(), language="text")
                if fields.get("error"):
                    st.caption("error")
                    st.code(fields["error"].rstrip(), language="text")
                if fields.get("result"):
                    st.code(fields["result"].rstrip(), language="text")
                if fields.get("exit_code") or fields.get("status"):
                    meta = " · ".join(
                        part
                        for part in (
                            f"exit {fields.get('exit_code')}" if fields.get("exit_code") else "",
                            fields.get("status") or "",
                        )
                        if part
                    )
                    st.caption(meta)
                continue
            if body:
                st.code(body.rstrip(), language="text")


def render_challenge_header(challenge: dict[str, Any]) -> None:
    solved_tone = "green" if challenge.get("solved") else "gray"
    status = str(challenge.get("status") or "downloaded")
    chips = " ".join(
        [
            chip(str(challenge.get("category") or "unknown"), "blue"),
            chip(f"{challenge.get('value', 'unknown')} pts", "gray"),
            chip("CTFd solved" if challenge.get("solved") else "CTFd unsolved", solved_tone),
            chip(f"agent {status}", agent_status_tone(status)),
        ]
    )
    st.markdown(
        f"""
        <div class="ctf-panel">
          <div class="ctf-title">{html.escape(str(challenge.get("name") or challenge.get("slug")))}</div>
          <div>{chips}</div>
          <div class="ctf-muted">{html.escape(str(challenge.get("slug")))} · {html.escape(str(challenge.get("workspace")))}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_challenge_body(challenge: dict[str, Any]) -> None:
        top = st.columns([2, 1, 1])
        top[0].write(f"**Workspace:** `{challenge.get('workspace')}`")
        top[1].write(f"**Agent:** {challenge.get('status')}")
        top[2].write(f"**CTFd:** {'solved' if challenge.get('solved') else 'unsolved'}")

        if challenge.get("connection_info"):
            st.code(str(challenge["connection_info"]), language="text")

        flags = challenge.get("flag_candidates") or []
        if flags:
            st.success("Flag candidates")
            st.code("\n".join(flags), language="text")

        followup_key = f"followup-{challenge['slug']}"
        st.text_area(
            "Follow-up instructions",
            key=followup_key,
            placeholder="Optional: tell the selected agent what to try next before clicking Continue.",
        )

        st.caption("Agent controls")
        controls = st.columns([1.25, 1.45, 1.25, 1.45, 0.8, 1.25, 1.05])
        disabled = challenge.get("status") == "running"
        if controls[0].button("Start Claude", key=f"start-claude-{challenge['slug']}", disabled=disabled):
            challenge_dir = resolve_challenge_dir(output_dir(), challenge["slug"])
            run_background(f"start:{challenge['slug']}", run_claude, challenge_dir, "start", "")
            st.rerun()
        if controls[1].button("Continue Claude", key=f"continue-claude-{challenge['slug']}", disabled=disabled):
            challenge_dir = resolve_challenge_dir(output_dir(), challenge["slug"])
            run_background(
                f"continue:{challenge['slug']}",
                run_claude,
                challenge_dir,
                "continue",
                st.session_state.get(followup_key, ""),
            )
            st.rerun()

        if controls[2].button("Start Codex", key=f"start-codex-{challenge['slug']}", disabled=disabled):
            challenge_dir = resolve_challenge_dir(output_dir(), challenge["slug"])
            run_background(f"codex-start:{challenge['slug']}", run_codex, challenge_dir, "start", "")
            st.rerun()

        if controls[3].button("Continue Codex", key=f"continue-codex-{challenge['slug']}", disabled=disabled):
            challenge_dir = resolve_challenge_dir(output_dir(), challenge["slug"])
            run_background(
                f"codex-continue:{challenge['slug']}",
                run_codex,
                challenge_dir,
                "continue",
                st.session_state.get(followup_key, ""),
            )
            st.rerun()

        if controls[4].button("Stop", key=f"stop-{challenge['slug']}", disabled=not disabled):
            challenge_dir = resolve_challenge_dir(output_dir(), challenge["slug"])
            stop_running_agent(challenge_dir)
            st.rerun()

        if controls[5].button("Mark succeeded", key=f"succeed-{challenge['slug']}"):
            challenge_dir = resolve_challenge_dir(output_dir(), challenge["slug"])
            mark_agent_succeeded(challenge_dir)
            st.rerun()

        details_loaded = challenge["slug"] in detail_slugs()
        if controls[6].button(
            "Hide logs" if details_loaded else "Show logs",
            key=f"details-{challenge['slug']}",
        ):
            set_detail_slug(challenge["slug"], not details_loaded)
            st.rerun()

        if not details_loaded:
            st.caption("Logs and parsed activity are paused for this challenge. Click Show logs to inspect them.")
            return

        current_view = detail_views().get(challenge["slug"], "Runs")
        view = st.segmented_control(
            "Detail view",
            DETAIL_VIEWS,
            default=current_view if current_view in DETAIL_VIEWS else "Runs",
            key=f"detail-view-{challenge['slug']}",
            label_visibility="collapsed",
        )
        if view != current_view:
            set_detail_view(challenge["slug"], str(view))
            st.rerun()
        view = str(view or current_view or "Runs")

        if view == "Runs":
            runs = challenge.get("runs") or []
            if runs:
                st.dataframe(
                    [
                        {
                            "started": run.get("started_at"),
                            "action": run.get("action"),
                            "status": run.get("status"),
                            "returncode": run.get("returncode"),
                        }
                        for run in reversed(runs)
                    ],
                    width='stretch',
                    hide_index=True,
                )
            else:
                st.caption("No runs yet.")
        elif view == "Claude last":
            render_log_panel(
                challenge.get("claude_last_message") or "No Claude output yet.",
                height=LAST_MESSAGE_HEIGHT,
                wrap=True,
            )
        elif view == "Claude activity":
            with st.container(height=ACTIVITY_HEIGHT, border=True):
                render_activity_events(challenge.get("claude_activity_events") or [], assistant_label="Claude")
        elif view == "Claude raw":
            render_log_panel(
                challenge.get("claude_log_tail") or "No Claude log yet.",
                height=LOG_TAIL_HEIGHT,
                wrap=False,
            )
        elif view == "Codex activity":
            with st.container(height=ACTIVITY_HEIGHT, border=True):
                render_activity_events(challenge.get("codex_activity_events") or [], assistant_label="Codex")
        elif view == "Codex last":
            render_log_panel(
                challenge.get("codex_last_message") or "No Codex output yet.",
                height=LAST_MESSAGE_HEIGHT,
                wrap=True,
            )
        elif view == "Codex raw":
            render_log_panel(
                challenge.get("codex_log_tail") or "No Codex log yet.",
                height=LOG_TAIL_HEIGHT,
                wrap=False,
            )


def render_challenge(challenge: dict[str, Any], expanded: bool = False) -> None:
    if expanded:
        render_challenge_header(challenge)
        render_challenge_body(challenge)
        return
    title = (
        f"{status_icon(challenge)} {challenge.get('name')} "
        f"· {challenge.get('value', 'unknown')} pts · {status_label(challenge)}"
    )
    with st.expander(title, expanded=False):
        render_challenge_body(challenge)


def render_compact_dashboard(challenges: list[dict[str, Any]]) -> None:
    st.subheader("Challenge workspace")
    selected_slug = st.session_state.get("selected_challenge_slug")
    if not selected_slug and challenges:
        running = next((challenge for challenge in challenges if challenge.get("status") == "running"), None)
        selected_slug = (running or challenges[0])["slug"]
        st.session_state["selected_challenge_slug"] = selected_slug

    challenge_by_slug = {challenge["slug"]: challenge for challenge in challenges}
    slugs = list(challenge_by_slug)
    selected_slug = selected_slug if selected_slug in challenge_by_slug else slugs[0]
    new_slug = st.selectbox(
        "Open challenge",
        slugs,
        index=slugs.index(selected_slug),
        format_func=lambda slug: (
            f"{status_icon(challenge_by_slug[slug])} "
            f"{challenge_by_slug[slug].get('category') or 'unknown'} · "
            f"{challenge_by_slug[slug].get('name')} · "
            f"{challenge_by_slug[slug].get('status')}"
        ),
    )
    if new_slug != selected_slug:
        st.session_state["selected_challenge_slug"] = new_slug
        st.rerun()

    selected = challenge_by_slug.get(new_slug)
    if selected:
        render_challenge(selected, expanded=True)

    st.subheader("Overview")
    table_rows = [
        {
            "selected": "yes" if challenge["slug"] == new_slug else "",
            "category": challenge.get("category") or "",
            "name": challenge.get("name") or challenge.get("slug"),
            "value": challenge.get("value"),
            "ctfd": "solved" if challenge.get("solved") else "unsolved",
            "agent": challenge.get("status"),
            "slug": challenge.get("slug"),
        }
        for challenge in challenges
    ]
    st.dataframe(
        table_rows,
        width="stretch",
        hide_index=True,
        height=min(520, 38 + 35 * len(table_rows)),
        column_config={
            "selected": st.column_config.TextColumn("open", width="small"),
            "category": st.column_config.TextColumn("category", width="medium"),
            "name": st.column_config.TextColumn("challenge", width="large"),
            "value": st.column_config.NumberColumn("pts", width="small"),
            "ctfd": st.column_config.TextColumn("CTFd", width="small"),
            "agent": st.column_config.TextColumn("agent", width="small"),
            "slug": st.column_config.TextColumn("slug", width="medium"),
        },
    )


@st.fragment(run_every=REFRESH_INTERVAL)
def render_live_dashboard() -> None:
    out = output_dir()
    out.mkdir(parents=True, exist_ok=True)
    harness = load_harness_state(out)
    challenges = collect_dashboard(
        out,
        raw_log_limit=raw_log_limit(),
        detail_slugs=detail_slugs(),
        detail_views=detail_views(),
    )

    render_operation_status(harness)
    render_metrics(challenges)
    st.caption(f"Live refresh: every {REFRESH_INTERVAL}")

    if st.button("Refresh"):
        st.rerun()

    if not challenges:
        st.info("No downloaded challenges yet. Use the sidebar to download from CTFd.")
        return

    status_filter = st.segmented_control(
        "Status",
        ["All", "Unsolved", "Solved", "Running", "Succeeded", "Failed", "Stopped"],
        default="All",
    )
    if status_filter == "Solved":
        challenges = [challenge for challenge in challenges if challenge.get("solved")]
    elif status_filter == "Unsolved":
        challenges = [challenge for challenge in challenges if not challenge.get("solved")]
    elif status_filter == "Running":
        challenges = [challenge for challenge in challenges if challenge.get("status") == "running"]
    elif status_filter == "Succeeded":
        challenges = [challenge for challenge in challenges if challenge.get("status") == "succeeded"]
    elif status_filter == "Failed":
        challenges = [challenge for challenge in challenges if challenge.get("status") == "failed"]
    elif status_filter == "Stopped":
        challenges = [challenge for challenge in challenges if challenge.get("status") == "stopped"]

    if not challenges:
        st.info("No challenges match this filter.")
        return

    if st.session_state.get("compact_mode", True):
        render_compact_dashboard(challenges)
    else:
        for category, items in grouped(challenges).items():
            solved = sum(1 for challenge in items if challenge.get("solved"))
            st.subheader(f"{category} ({solved}/{len(items)} solved)")
            for challenge in items:
                render_challenge(challenge)


def main() -> None:
    st.set_page_config(page_title="CTF Solver Dashboard", layout="wide")
    apply_styles()
    st.title("CTF Solver Dashboard")
    st.caption("Download CTFd challenges, run Claude or Codex in per-challenge sandboxes, and monitor progress.")
    out = output_dir()
    out.mkdir(parents=True, exist_ok=True)
    render_sidebar(load_harness_state(out))
    render_live_dashboard()


if __name__ == "__main__":
    main()
