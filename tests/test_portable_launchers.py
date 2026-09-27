"""Offline launcher contracts: subprocesses run only a disposable uv stub."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import tomllib
import unittest

ROOT = Path(__file__).resolve().parents[1]


class DependencyPlatformTests(unittest.TestCase):
    def test_magic_dependencies_are_platform_scoped(self):
        project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        requirements = project["project"]["dependencies"]
        self.assertIn("python-magic-bin>=0.4.14; sys_platform == 'win32'", requirements)
        self.assertIn("python-magic>=0.4.27; sys_platform != 'win32'", requirements)

    def test_lock_preserves_both_platform_selections(self):
        lock = tomllib.loads((ROOT / "uv.lock").read_text(encoding="utf-8"))
        project = next(p for p in lock["package"] if p["name"] == "clank-the-flag")
        markers = {d["name"]: d.get("marker") for d in project["dependencies"]}
        self.assertEqual(markers["python-magic"], "sys_platform != 'win32'")
        self.assertEqual(markers["python-magic-bin"], "sys_platform == 'win32'")
        magic = next(p for p in lock["package"] if p["name"] == "python-magic")
        self.assertTrue(any(w["url"].endswith("none-any.whl") for w in magic["wheels"]))


@unittest.skipIf(os.name == "nt", "POSIX scripts run under Linux CI")
class ShellLauncherTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ctf launcher ")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "checkout with spaces"
        (self.root / "scripts").mkdir(parents=True)
        for file in ("setup_mcp.sh", "start_backend.sh", "start_full.sh"):
            shutil.copyfile(ROOT / file, self.root / file)
        (self.root / "scripts" / "mcp_smoke.py").touch()
        self.bin = Path(self.temp.name) / "stub bin"
        self.bin.mkdir()
        self.log = Path(self.temp.name) / "calls.jsonl"
        stub = self.bin / "uv"
        stub.write_text(
            "#!" + sys.executable + "\n"
            "import json,os,pathlib,sys\n"
            "keys=['PYTHONPATH','PYTHONUTF8','CTFTOOLKIT_WORKSPACE','CTFTOOLKIT_DB_PATH','CTFTOOLKIT_DOWNLOADS','CTF_HARNESS_AGENT_MCP_URL']\n"
            "with open(os.environ['TEST_CALL_LOG'],'a') as f: f.write(json.dumps({'args':sys.argv[1:],'cwd':os.getcwd(),'env':{k:os.environ.get(k) for k in keys}})+'\\n')\n"
            "sys.exit(int(os.environ.get('TEST_EXIT','0')))\n",
            encoding="utf-8",
        )
        stub.chmod(0o755)
        self.env = os.environ.copy()
        for key in ("CTFTOOLKIT_WORKSPACE", "CTFTOOLKIT_DB_PATH", "CTFTOOLKIT_DOWNLOADS", "CTF_HARNESS_AGENT_MCP_URL"):
            self.env.pop(key, None)
        self.env.update(PATH=str(self.bin) + os.pathsep + self.env["PATH"],
                        PYTHONPATH="retained path", TEST_CALL_LOG=str(self.log),
                        CTF_WORKDIR=str(self.root / "workspace"), CTF_HARNESS_START_AGENT_MCP="0")

    def run_script(self, script, args=(), code=0):
        self.log.unlink(missing_ok=True)
        result = subprocess.run(["bash", str(self.root / script), *args],
                                cwd=self.temp.name, env={**self.env, "TEST_EXIT": str(code)},
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, code, result.stderr)
        return [json.loads(line) for line in self.log.read_text().splitlines()]

    def test_backend_modes_arguments_environment_and_exit(self):
        modes = [
            ([], ["run", "python", "-m", "ctf_core.server"]),
            (["--doctor"], ["run", "python", "scripts/doctor.py"]),
            (["--smoke"], ["run", "python", "scripts/mcp_smoke.py"]),
            (["--http"], ["run", "python", "scripts/mcp_http.py"]),
        ]
        for flags, expected in modes:
            for code in (0, 37):
                with self.subTest(flags=flags, code=code):
                    calls = self.run_script("start_backend.sh", [*flags, "value with spaces"], code)
                    self.assertEqual(len(calls), 1)
                    call = calls[0]
                    self.assertEqual(call["args"], [*expected, "value with spaces"])
                    self.assertTrue(Path(call["cwd"]).samefile(self.root))
                    self.assertEqual(call["env"]["PYTHONPATH"], str(self.root / "src") + ":retained path")
                    self.assertEqual(call["env"]["CTFTOOLKIT_WORKSPACE"], str(self.root / "workspace"))

    def test_setup_stops_on_failure_and_runs_doctor_after_success(self):
        calls = self.run_script("setup_mcp.sh", ["value with spaces"])
        self.assertEqual([c["args"] for c in calls], [
            ["run", "python", "scripts/setup.py", "--write", "--auth-check", "value with spaces"],
            ["run", "python", "scripts/doctor.py"],
        ])
        self.assertEqual(len(self.run_script("setup_mcp.sh", code=37)), 1)

    def test_dashboard_uses_explicit_local_backend_without_background_processes(self):
        for code in (0, 37):
            with self.subTest(code=code):
                calls = self.run_script("start_full.sh", ["--server.port", "8502"], code)
                self.assertEqual(len(calls), 1)
                self.assertEqual(calls[0]["args"], [
                    "run", "streamlit", "run", str(self.root / "streamlit_app.py"),
                    "--server.port", "8502",
                ])
                self.assertEqual(calls[0]["env"]["CTF_HARNESS_AGENT_MCP_URL"], "http://127.0.0.1:8000/mcp")


if __name__ == "__main__":
    unittest.main()
