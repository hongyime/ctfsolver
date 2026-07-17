"""Interactive CLI menu for CTF Toolkit — launched by start_toolkit.bat → main.py."""
import os
import subprocess
import sys

import questionary
from rich.console import Console
from rich.table import Table

console = Console()


def main() -> None:
    """Top-level entry point — keeps showing the main menu until user exits."""
    while True:
        try:
            _show_main_menu()
        except KeyboardInterrupt:
            console.print("\n[yellow]Exiting...[/yellow]")
            return


def _show_main_menu() -> None:
    console.print("\n[bold cyan]CTF Toolkit[/bold cyan]")

    choice = questionary.select(
        "Select an option:",
        choices=[
            "1. MCP Server Management",
            "2. Challenge Management",
            "3. Reconnaissance Tools",
            "4. Web Exploitation Tools",
            "5. Binary Exploitation Tools",
            "6. Forensics Tools",
            "7. Crypto Tools",
            "8. Database Management",
            "9. System Management",
            "0. Exit",
        ],
    ).ask()

    if choice is None or choice.startswith("0"):
        console.print("[yellow]Exiting...[/yellow]")
        sys.exit(0)
    elif choice.startswith("1"):
        _show_mcp_menu()
    elif choice.startswith("2"):
        _show_challenge_menu()
    elif choice.startswith("3"):
        _show_tool_menu("Reconnaissance", ["nmap", "masscan", "httpx", "amass", "assetfinder"])
    elif choice.startswith("4"):
        _show_tool_menu("Web Exploitation", ["sqlmap", "ffuf", "nikto", "gobuster", "wfuzz"])
    elif choice.startswith("5"):
        _show_tool_menu("Binary Exploitation", ["checksec", "pwntools", "gdb", "radare2"])
    elif choice.startswith("6"):
        _show_tool_menu("Forensics", ["volatility", "exiftool", "tshark", "binwalk"])
    elif choice.startswith("7"):
        _show_tool_menu("Crypto", ["hashcat", "john"])
    elif choice.startswith("8"):
        _show_db_menu()
    elif choice.startswith("9"):
        _show_system_menu()


# ── MCP Server Management ──────────────────────────────────────────────────

def _show_mcp_menu() -> None:
    choice = questionary.select(
        "MCP Server Management:",
        choices=[
            "1.1 Start MCP Server (stdio)",
            "1.2 View Server Logs",
            "1.3 Test MCP Connection",
            "Back to Main Menu",
        ],
    ).ask()

    if choice is None or choice.startswith("Back"):
        return

    if choice.startswith("1.1"):
        console.print("[green]Starting MCP server (Ctrl+C to stop)...[/green]")
        subprocess.run(["uv", "run", "python", "-m", "ctf_core.server"])

    elif choice.startswith("1.2"):
        log_path = "logs/ctfsolver.log"
        if os.path.exists(log_path):
            with open(log_path) as f:
                console.print(f.read())
        else:
            console.print(f"[red]Log file not found: {log_path}[/red]")

    elif choice.startswith("1.3"):
        console.print("[cyan]Testing MCP connection...[/cyan]")
        try:
            result = subprocess.run(
                ["uv", "run", "python", "-c",
                 "import asyncio; from ctf_core.db import init_database; asyncio.run(init_database()); print('DB OK')"],
                capture_output=True, text=True, timeout=10,
            )
            console.print(result.stdout or result.stderr)
        except Exception as e:
            console.print(f"[red]Connection test failed: {e}[/red]")


# ── Challenge Management ───────────────────────────────────────────────────

def _show_challenge_menu() -> None:
    choice = questionary.select(
        "Challenge Management:",
        choices=[
            "2.1 Ingest Challenge Files",
            "2.2 Search Writeups",
            "2.3 Web Search",
            "2.4 List Challenges",
            "Back to Main Menu",
        ],
    ).ask()

    if choice is None or choice.startswith("Back"):
        return

    if choice.startswith("2.1"):
        directory = questionary.path("Enter directory path:").ask()
        challenge_id = questionary.text("Enter challenge ID (e.g. htb-machine-name):").ask()
        if directory and challenge_id:
            try:
                from ctf_core.utils.file_ingester import ingest_challenge_files
                result = ingest_challenge_files(directory, challenge_id)
                console.print(f"[green]Ingested {len(result)} files.[/green]")
                _print_file_inventory(result)
            except Exception as e:
                console.print(f"[red]Ingestion failed: {e}[/red]")

    elif choice.startswith("2.2"):
        challenge_name = questionary.text("Challenge name:").ask()
        category = questionary.text("Category (optional):").ask() or ""
        if challenge_name:
            try:
                from ctf_core.scrapers.writeup_scraper import search_writeups
                writeups = search_writeups(challenge_name, category, limit=10)
                if writeups:
                    console.print(f"\n[green]Found {len(writeups)} writeups:[/green]")
                    for w in writeups:
                        console.print(f"  • {w['title']} — {w['source_url']}")
                else:
                    console.print("[yellow]No writeups found.[/yellow]")
            except Exception as e:
                console.print(f"[red]Writeup search failed: {e}[/red]")

    elif choice.startswith("2.3"):
        query = questionary.text("Search query:").ask()
        if query:
            try:
                from ctf_core.scrapers.web_search import search
                results = search(query, limit=5)
                if results:
                    for r in results:
                        console.print(f"  • {r['title']}\n    {r['url']}")
                else:
                    console.print("[yellow]No results found.[/yellow]")
            except Exception as e:
                console.print(f"[red]Search failed: {e}[/red]")

    elif choice.startswith("2.4"):
        _list_challenges()


def _print_file_inventory(inventory: dict) -> None:
    if not inventory:
        return
    table = Table(title="Ingested Files")
    table.add_column("File")
    table.add_column("Type")
    table.add_column("Size")
    table.add_column("Suggested Tools")
    for name, info in inventory.items():
        table.add_row(
            name,
            info.get("file_type", "?"),
            str(info.get("file_size", 0)),
            ", ".join(info.get("suggested_tools", [])),
        )
    console.print(table)


def _list_challenges() -> None:
    try:
        import sqlite3, os
        db_path = os.environ.get("CTFTOOLKIT_DB_PATH", "ctf_state.db")
        con = sqlite3.connect(db_path)
        con.row_factory = sqlite3.Row
        rows = con.execute("SELECT challenge_id, name, category, status FROM challenges ORDER BY created_at DESC LIMIT 50").fetchall()
        con.close()
        if not rows:
            console.print("[yellow]No challenges found.[/yellow]")
            return
        table = Table(title="Challenges")
        table.add_column("ID")
        table.add_column("Name")
        table.add_column("Category")
        table.add_column("Status")
        for r in rows:
            table.add_row(r["challenge_id"], r["name"], r["category"] or "", r["status"])
        console.print(table)
    except Exception as e:
        console.print(f"[red]Database query failed: {e}[/red]")


# ── Tool menus ─────────────────────────────────────────────────────────────

def _show_tool_menu(category: str, tools: list[str]) -> None:
    choices = [f"Run {t}" for t in tools] + ["Back to Main Menu"]
    choice = questionary.select(f"{category} Tools:", choices=choices).ask()

    if choice is None or choice.startswith("Back"):
        return

    tool_name = choice.removeprefix("Run ")
    target = questionary.text(f"Target / arguments for {tool_name}:").ask()
    if not target:
        return

    console.print(f"[cyan]Running {tool_name} against {target}...[/cyan]")
    console.print("[yellow](This runs via Docker — ensure Docker is running.)[/yellow]")

    try:
        import asyncio
        from ctf_core.docker_runner import DockerRunner
        runner = DockerRunner()
        result = asyncio.run(runner.run_tool(tool_name, target.split()))
        console.print(result.get("stdout", "") or result.get("stderr", "No output."))
    except Exception as e:
        console.print(f"[red]Tool execution failed: {e}[/red]")


# ── Database Management ────────────────────────────────────────────────────

def _show_db_menu() -> None:
    choice = questionary.select(
        "Database Management:",
        choices=[
            "8.1 Show recent actions",
            "8.2 Show captured flags",
            "8.3 Show token usage summary",
            "Back to Main Menu",
        ],
    ).ask()

    if choice is None or choice.startswith("Back"):
        return

    try:
        import sqlite3
        db_path = os.environ.get("CTFTOOLKIT_DB_PATH", "ctf_state.db")
        con = sqlite3.connect(db_path)
        con.row_factory = sqlite3.Row

        if choice.startswith("8.1"):
            rows = con.execute(
                "SELECT timestamp, tool_used, command_string FROM action_log ORDER BY timestamp DESC LIMIT 20"
            ).fetchall()
            for r in rows:
                console.print(f"[dim]{r['timestamp']}[/dim] {r['tool_used']}: {r['command_string'][:80]}")

        elif choice.startswith("8.2"):
            rows = con.execute("SELECT flag_value, timestamp FROM flags ORDER BY timestamp DESC LIMIT 50").fetchall()
            if rows:
                for r in rows:
                    console.print(f"  {r['flag_value']} ({r['timestamp']})")
            else:
                console.print("[yellow]No flags captured yet.[/yellow]")

        elif choice.startswith("8.3"):
            rows = con.execute(
                "SELECT tool_name, SUM(total_tokens) AS total FROM token_usage GROUP BY tool_name ORDER BY total DESC LIMIT 20"
            ).fetchall()
            if rows:
                table = Table(title="Token Usage by Tool")
                table.add_column("Tool")
                table.add_column("Total Tokens")
                for r in rows:
                    table.add_row(r["tool_name"] or "unknown", str(r["total"]))
                console.print(table)
            else:
                console.print("[yellow]No token usage data yet.[/yellow]")

        con.close()
    except Exception as e:
        console.print(f"[red]Database error: {e}[/red]")


# ── System Management ──────────────────────────────────────────────────────

def _show_system_menu() -> None:
    choice = questionary.select(
        "System Management:",
        choices=[
            "9.1 Health check",
            "9.2 Validate .env config",
            "9.3 List Docker images",
            "Back to Main Menu",
        ],
    ).ask()

    if choice is None or choice.startswith("Back"):
        return

    if choice.startswith("9.1"):
        _health_check()
    elif choice.startswith("9.2"):
        _validate_env()
    elif choice.startswith("9.3"):
        _list_docker_images()


def _health_check() -> None:
    from ctf_core.utils.resilience import _is_internet_available
    internet = _is_internet_available()
    console.print(f"Internet: {'[green]OK[/green]' if internet else '[red]OFFLINE[/red]'}")

    db_path = os.environ.get("CTFTOOLKIT_DB_PATH", "ctf_state.db")
    db_ok = os.path.exists(db_path)
    console.print(f"Database: {'[green]OK[/green]' if db_ok else '[red]NOT FOUND[/red]'} ({db_path})")

    try:
        import docker
        client = docker.from_env()
        client.ping()
        console.print("Docker: [green]OK[/green]")
    except Exception as e:
        console.print(f"Docker: [red]UNAVAILABLE[/red] ({e})")


def _validate_env() -> None:
    required = ["CTFTOOLKIT_WORKSPACE", "CTFTOOLKIT_DB_PATH"]
    for key in required:
        val = os.environ.get(key)
        if val:
            console.print(f"[green]{key}[/green] = {val}")
        else:
            console.print(f"[yellow]{key}[/yellow] = (not set — using default)")


def _list_docker_images() -> None:
    try:
        import docker
        client = docker.from_env()
        images = client.images.list(filters={"reference": "ctftoolkit/*"})
        if images:
            for img in images:
                tags = ", ".join(img.tags) if img.tags else img.id[:12]
                console.print(f"  {tags}")
        else:
            console.print("[yellow]No ctftoolkit Docker images found. Run setup.bat to build them.[/yellow]")
    except Exception as e:
        console.print(f"[red]Docker error: {e}[/red]")
