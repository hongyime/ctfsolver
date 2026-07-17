#!/usr/bin/env python3
"""
Tier 4 Runner: Real CTF Platform Integration

Human-in-the-loop tests for real CTF platforms.

NOTE: This tier requires human participation for flag submission
and challenge interpretation.

Usage:
    python tests/hands_on/run_tier4.py          # Show instructions
    python tests/hands_on/run_tier4.py --guide # Show detailed guide
"""

import sys
import argparse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from tests.hands_on._lib import print_banner, print_section


TIER4_CONTENT = """
================================================================================
                    TIER 4: REAL CTF PLATFORM INTEGRATION
================================================================================

This tier requires human participation. The CTF Toolkit assists with
reconnaissance and analysis, but you must:

  1. Interpret results and identify actual vulnerabilities
  2. Manually craft exploits or use appropriate tools
  3. Extract flags from outputs
  4. Submit flags through the platform interface

================================================================================
                           PLATFORM SETUP INSTRUCTIONS
================================================================================

------------------------------------------------------------------------------
1. picoCTF Playground (Free, No Account Required for Practice)
------------------------------------------------------------------------------

Website: https://play.picoctf.org/

Setup:
  1. Visit https://play.picoctf.org/
  2. Click "Practice" (no login needed)
  3. Select any challenge category (Web, Forensics, Crypto, etc.)
  4. Note the target IP/URL and challenge description

Using CTF Toolkit:
  
  # Example: Web exploitation challenge
  python -c "
  from src.ctf_core.docker_runner import DockerRunner
  from src.ctf_core.utils.flag_detector import FlagPatternDetector
  
  async def solve():
      runner = DockerRunner()
      detector = FlagPatternDetector()
      
      # Scan target
      result = await runner.run_tool('nmap', ['-sV', 'TARGET_IP'])
      print(result['stdout'])
      
      # Run SQLMap on vulnerable parameter
      sqlmap = await runner.run_tool('sqlmap', [
          '-u', 'http://TARGET_URL/?id=1',
          '--batch', '--dbs'
      ])
      
      # Extract flags from output
      flags = detector.extract_flags(sqlmap['stdout'])
      if flags:
          print(f'[!] FLAGS: {flags}')
  
  import asyncio
  asyncio.run(solve())
  "

Manual Steps:
  - Analyze scan results
  - Identify vulnerability
  - Extract flag manually or with tool help
  - Submit via web interface

------------------------------------------------------------------------------
2. HackTheBox Academy (Free Modules Available)
------------------------------------------------------------------------------

Website: https://academy.hackthebox.com/

Setup:
  1. Create free account at https://academy.hackthebox.com/
  2. Access free modules (e.g., "Introduction to Cybersecurity")
  3. Start the VPN: openvpn your-connection-file.ovpn
  4. Access assigned targets

Using CTF Toolkit:

  # After connecting to HTB VPN
  python -c "
  from src.ctf_core.docker_runner import DockerRunner
  
  async def scan():
      runner = DockerRunner()
      
      # Scan assigned HTB target
      result = await runner.run_tool('nmap', [
          '-sV', '-sC', '10.10.10.100'  # Your assigned IP
      ])
      print(result['stdout'])
  
  import asyncio
  asyncio.run(scan())
  "

Note: Always respect HTB's terms of service and rate limits.

------------------------------------------------------------------------------
3. TryHackMe (Beginner Friendly)
------------------------------------------------------------------------------

Website: https://tryhackme.com/

Setup:
  1. Create free account
  2. Deploy a target machine
  3. Note the target IP
  4. Complete challenges

Using CTF Toolkit:

  # Similar to HTB, but with TryHackMe's VPN
  openvpn your-connection-file.ovpn

  python -c "
  from src.ctf_core.docker_runner import DockerRunner
  
  async def scan():
      runner = DockerRunner()
      
      # Scan TryHackMe target
      result = await runner.run_tool('nmap', [
          '-sV', '-sC', '-p-', 'TARGET_IP'
      ])
      print(result['stdout'])
  
  import asyncio
  asyncio.run(scan())
  "

------------------------------------------------------------------------------
4. Local CTF Events / Jeopardy-style CTFs
------------------------------------------------------------------------------

For self-hosted CTF events:

1. CTFd Platform (https://ctfd.io/)
   - Deploy your own CTF platform
   - Use provided challenge URLs
   - Follow same workflow as picoCTF

2. Run Your Own:
   - Use Docker to host vulnerable apps
   - Create custom challenges
   - Test toolkit end-to-end

================================================================================
                            WORKFLOW CHECKLIST
================================================================================

Before Starting:
  [ ] Docker images loaded: docker images | grep ctftoolkit
  [ ] Database initialized: python -c "from src.ctf_core.db import init_database; import asyncio; asyncio.run(init_database())"
  [ ] VPN connected (if required by platform)
  [ ] Target IP/URL noted

During Challenge:
  [ ] Run initial recon with Nmap
  [ ] Store results in database
  [ ] Identify services and versions
  [ ] Run targeted scans (SQLMap, etc.)
  [ ] Look for flags in all outputs
  [ ] Document findings

Flag Extraction:
  [ ] Check scan output for flag patterns
  [ ] Look in page source
  [ ] Check response headers
  [ ] Examine cookies/tokens
  [ ] Decode if necessary (base64, hex, etc.)

Submission:
  [ ] Verify flag format matches challenge
  [ ] Submit through platform interface
  [ ] Score updates automatically

================================================================================
                            COMMON FLAG PATTERNS
================================================================================

CTF-Style:
  - CTF{this_is_the_flag}
  - flag{another_flag}
  - picoCTF{flag_here}

Hex-encoded:
  - 5ebe2294ecd0e0f08eab7690d2a6ee69

Base64:
  - S0tQVAhZmxhZ3t0ZXN0X2ZsYWd9 (decodes to: KCTF!flag{test_flag})

UUID:
  - 550e8400-e29b-41d4-a716-446655440000

================================================================================
                         TROUBLESHOOTING COMMON ISSUES
================================================================================

Issue: Nmap scan times out
  - Check VPN is connected
  - Verify target IP is correct
  - Try with -T4 flag for faster scan

Issue: SQLMap returns no results
  - Check URL is correct and accessible
  - Verify parameter is actually injectable
  - Try adding --random-agent

Issue: Flag not detected
  - Check page source (Ctrl+U in browser)
  - Look in response headers
  - Try different encoding (base64, hex)

Issue: Database locked
  - Close other Python processes
  - Delete ctf_state.db-wal and ctf_state.db-shm files

================================================================================
                             VALIDATION CHECKLIST
================================================================================

After completing Tier 4 challenges, verify:

  [ ] Can run nmap scans against remote targets
  [ ] Can store scan results in database
  [ ] Can use SQLMap for web testing
  [ ] Can detect flags in various formats
  [ ] Can interpret and act on scan results
  [ ] Can submit flags to platform

================================================================================
                              DOCUMENT YOUR RESULTS
================================================================================

After completing challenges, document:

1. Challenge Name:
2. Platform:
3. Target:
4. Tools Used:
5. Flag(s) Found:
6. Time Taken:
7. Notes/Learnings:

This helps track your progress and identify areas for improvement.

================================================================================
"""


def run_interactive():
    """Run interactive Tier 4 guide."""
    print_banner()
    print_section("Tier 4: Real CTF Platform Integration")
    print(TIER4_CONTENT)


def run_picoctf_guide():
    """Show picoCTF-specific guide."""
    print_banner()
    print_section("picoCTF Quick Start Guide")
    
    print("""
1. Visit https://play.picoctf.org/practice

2. Select a challenge (e.g., "Where Can I RCE?" or "Irish Name DB")

3. Note the target URL/IP

4. Use CTF Toolkit to assist:
   
   python -c "
   from src.ctf_core.docker_runner import DockerRunner
   from src.ctf_core.utils.flag_detector import FlagPatternDetector
   
   async def scan():
       runner = DockerRunner()
       detector = FlagPatternDetector()
       
       # Replace with actual target
       result = await runner.run_tool('nmap', ['-sV', 'TARGET_IP'])
       print(result['stdout'])
       
       # Look for flags
       flags = detector.extract_flags(result['stdout'])
       if flags:
           print(f'[!] Found: {flags}')
   
   import asyncio
   asyncio.run(scan())
   "

5. Analyze results, extract flag, submit!

Recommended starting challenges:
   - " Glory of the Garden" (Forensics)
   - "Java Script" (Web)
   - "Insp3ct0r" (Web)
""")


def run_htb_guide():
    """Show HackTheBox Academy guide."""
    print_banner()
    print_section("HackTheBox Academy Quick Start")
    
    print("""
1. Create account at https://academy.hackthebox.com/

2. Start free module: "Introduction to Cybersecurity"

3. Download VPN file from Access page

4. Connect VPN:
   openvpn lab_access_<username>.ovpn

5. Deploy target machine from module

6. Use CTF Toolkit:
   
   python -c "
   from src.ctf_core.docker_runner import DockerRunner
   import asyncio
   
   async def scan():
       runner = DockerRunner()
       
       # Replace with your target IP
       result = await runner.run_tool('nmap', [
           '-sV', '-sC', '-p-', '10.10.10.100'
       ])
       print(result['stdout'])
   
   asyncio.run(scan())
   "

7. Complete module challenges!

Note: Respect rate limits and terms of service!
""")


def main():
    parser = argparse.ArgumentParser(description="Tier 4 Real CTF Platform Integration")
    parser.add_argument("--guide", "-g", action="store_true", help="Show full guide")
    parser.add_argument("--picoctf", "-p", action="store_true", help="picoCTF specific guide")
    parser.add_argument("--htb", action="store_true", help="HackTheBox specific guide")
    parser.add_argument("--checklist", "-c", action="store_true", help="Show validation checklist")
    
    args = parser.parse_args()
    
    if args.picoctf:
        run_picoctf_guide()
    elif args.htb:
        run_htb_guide()
    elif args.checklist:
        print_banner()
        print_section("Tier 4 Validation Checklist")
        print("""
TIER 4 VALIDATION CHECKLIST
==========================

Mark each item as completed:

Before Starting:
  [ ] Docker images loaded
  [ ] Database initialized
  [ ] VPN configured (if needed)
  [ ] Target identified

During Challenge:
  [ ] Initial recon completed
  [ ] Results stored in DB
  [ ] Services identified
  [ ] Flags detected

After Challenge:
  [ ] Flag submitted
  [ ] Score updated
  [ ] Notes documented

Self-Assessment:
  [ ] Comfortable with toolkit workflow
  [ ] Can interpret scan results
  [ ] Can extract flags from output
  [ ] Ready for real CTF competition

Sign-off:
  [ ] Ready for CTF competitions
  [ ] Toolkit workflow internalized
  [ ] Documentation reviewed
        """)
    else:
        run_interactive()


if __name__ == "__main__":
    main()
