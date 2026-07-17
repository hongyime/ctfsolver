"""Detects and handles sudo password prompts."""

import re
import subprocess
from typing import Optional

# Patterns that indicate sudo/password prompts
SUDO_PATTERNS = [
    r'\[sudo\] password for',
    r'password:',
    r'enter passphrase',
    r'authentication required',
    r'please enter sudo password',
    r'sorry, try again',
    r'sorry, a password is required',
    r'sudo: a password is required',
    r'sudo:.*password',
]

SUDO_PATTERN_REGEX = re.compile('|'.join(SUDO_PATTERNS), re.IGNORECASE)


def detect_sudo_prompt(stderr: str) -> bool:
    """
    Detect if stderr contains a sudo/password prompt.
    
    Args:
        stderr: Standard error output from subprocess
        
    Returns:
        True if sudo prompt detected, False otherwise
    """
    return bool(SUDO_PATTERN_REGEX.search(stderr))


def handle_sudo_prompt(process: subprocess.Popen) -> Optional[str]:
    """
    Handle a detected sudo prompt by terminating the process.
    
    Args:
        process: The subprocess to terminate
        
    Returns:
        Error message string
    """
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
    
    return ("Error: Interactive sudo prompt detected. "
            "Commands requiring elevated privileges are not supported. "
            "Please run tools that don't require sudo.")
