# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller spec file for CTF Toolkit MCP Server.

This creates a single-file executable that includes all dependencies.
Usage:
    pyinstaller pyinstaller.spec
"""

import os
import sys
from pathlib import Path

# Project root - use current working directory
ROOT = Path.cwd()

block_cipher = None

# Collect all data files that need to be included
datas = [
    # Database schema
    (str(ROOT / 'schema' / 'init_db.sql'), 'schema'),
    
    # Skills directory
    (str(ROOT / 'skills'), 'skills'),
    
    # Configuration files
    (str(ROOT / 'config'), 'config'),
    
    # MCP configuration templates
    (str(ROOT / 'mcp.json'), '.'),
    (str(ROOT / 'mcp-windows.json'), '.'),
]

# Hidden imports for packages that are dynamically loaded
hiddenimports = [
    # Core dependencies
    'mcp',
    'mcp.server',
    'mcp.server.fastmcp',
    'aiosqlite',
    'docker',
    'xmltodict',
    'pydantic',
    
    # Platform-specific modules
    'ctf_core.platform',
    'ctf_core.platform.windows',
    'ctf_core.platform.macos',
    'ctf_core.platform.linux',
    
    # WASM runtime (optional)
    'wasmtime',
    'wasmedge',
    'wasmer',
    
    # Parsers
    'ctf_core.parsers.nmap_parser',
    'ctf_core.parsers.ferox_parser',
    'ctf_core.parsers.sploit_parser',
    'ctf_core.parsers.hashcat_parser',
    'ctf_core.parsers.hydra_parser',
    'ctf_core.parsers.masscan_parser',
    'ctf_core.parsers.nikto_parser',
    'ctf_core.parsers.sqlmap_parser',
    'ctf_core.parsers.volatility_parser',
    'ctf_core.parsers.generic_parser',
    
    # Agents
    'ctf_core.agents.planner',
    'ctf_core.agents.executor',
    'ctf_core.agents.auto_prompter',
    
    # Utilities
    'ctf_core.utils.sanitize',
    'ctf_core.utils.sudo_guard',
    'ctf_core.utils.net_guard',
    
    # Database
    'ctf_core.db',
    
    # Docker runner
    'ctf_core.docker_runner',
    
]

# Binaries to include (if any)
binaries = []

# PyInstaller options
a = Analysis(
    [str(ROOT / 'src' / 'ctf_core' / 'server.py')],
    pathex=[str(ROOT / 'src')],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        # Exclude unnecessary modules to reduce size
        'test',
        'tests',
        'pytest',
        'unittest',
        'setuptools',
        'distutils',
        # Exclude development tools
        'mypy',
        'ruff',
        'black',
        'flake8',
        'isort',
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

# Create PYZ archive
pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

# Determine output name based on platform
if sys.platform == 'win32':
    exe_name = 'ctf-toolkit'
    extension = '.exe'
elif sys.platform == 'darwin':
    exe_name = 'ctf-toolkit'
    extension = ''
else:
    exe_name = 'ctf-toolkit'
    extension = ''

# Create executable
exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name=exe_name + extension,
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,  # Compress executable
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,  # Change to False for GUI application
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

# For macOS app bundle (optional)
# if sys.platform == 'darwin':
#     app = BUNDLE(
#         exe,
#         name=exe_name + '.app',
#         icon=None,
#         bundle_identifier='com.ctftoolkit',
#     )
