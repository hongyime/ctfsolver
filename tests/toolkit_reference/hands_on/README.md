# CTF Toolkit Hands-On Test Suite

Comprehensive validation suite for the CTF Toolkit, organized into 4 tiers from local testing to real CTF competitions.

## Quick Start

```bash
# Run all automated tests
python tests/hands_on/run_all.py

# Check prerequisites
python tests/hands_on/run_all.py --prereqs

# List all tiers
python tests/hands_on/run_all.py --list
```

## Tier Overview

| Tier | Name | Description | Time | Requirements |
|------|------|-------------|------|--------------|
| 1 | Local Environment | Core infrastructure without external dependencies | 2-5 min | Docker |
| 2 | Safe External Targets | Public vulnerable test sites | 5-15 min | Internet + Docker |
| 3 | Self-Hosted VMs | Docker vulnerable apps (DVWA, Juice Shop) | 15-30 min | Internet + Docker |
| 4 | Real CTF Platforms | picoCTF, HackTheBox, TryHackMe | Ongoing | Human + Internet |

## Running Individual Tiers

### Tier 1: Local Environment Tests

```bash
python tests/hands_on/run_tier1.py

# Or run specific test files
python tests/hands_on/tier1/t1_001_docker_images.py
python tests/hands_on/tier1/t1_002_database.py
python tests/hands_on/tier1/t1_003_sanitization.py
python tests/hands_on/tier1/t1_004_flag_detection.py
python tests/hands_on/tier1/t1_005_006_security_guards.py
python tests/hands_on/tier1/t1_007_mcp_health.py
```

**Tests:**
- T1-001: Docker image verification
- T1-002: Database initialization and CRUD operations
- T1-003: Command sanitization (valid and dangerous commands)
- T1-004: Flag detection in various output formats
- T1-005: Sudo prompt detection
- T1-006: Network isolation guards (private/public blocking)
- T1-007: MCP server health check

### Tier 2: Safe External Targets

```bash
# Full run (takes ~15 minutes)
python tests/hands_on/run_tier2.py

# Quick run (skip slow tests)
python tests/hands_on/run_tier2.py --quick
```

**Tests:**
- T2-001: Nmap scan against scanme.nmap.org
- T2-002: SQLMap detection on Acunetix vulnerable site
- T2-003: SearchSploit exploit database query
- T2-004: HTTP enumeration via Nmap scripts

### Tier 3: Self-Hosted Vulnerable Targets

```bash
# Setup Docker vulnerable targets first
python tests/hands_on/run_tier3.py --setup

# Run tests
python tests/hands_on/run_tier3.py

# Cleanup after
python tests/hands_on/run_tier3.py --cleanup

# Setup + test + cleanup in one command
python tests/hands_on/run_tier3.py --setup --cleanup
```

**Tests:**
- T3-001: DVWA Nmap scan
- T3-002: DVWA SQLMap testing
- T3-003: OWASP Juice Shop scanning
- T3-004: Complete CTF workflow

### Tier 4: Real CTF Platforms (Human-in-the-Loop)

```bash
# Show full guide
python tests/hands_on/run_tier4.py

# Quick start guides
python tests/hands_on/run_tier4.py --picoctf
python tests/hands_on/run_tier4.py --htb

# Show validation checklist
python tests/hands_on/run_tier4.py --checklist
```

**Platforms:**
- picoCTF (https://play.picoctf.org/) - Free, no account needed
- HackTheBox Academy (https://academy.hackthebox.com/) - Free modules
- TryHackMe (https://tryhackme.com/) - Beginner friendly

## Docker Vulnerable Targets

Tier 3 uses these vulnerable Docker images:

| Name | Image | Port | Description |
|------|-------|------|-------------|
| DVWA | vulnerables/web-dvwa | 8080 | Damn Vulnerable Web Application |
| Juice Shop | bkimminich/juice-shop | 3000 | OWASP Juice Shop |

### Manual Docker Setup

```bash
# Pull images
docker pull vulnerables/web-dvwa
docker pull bkimminich/juice-shop

# Run DVWA
docker run -d --name ctf-test-dvwa -p 8080:80 vulnerables/web-dvwa

# Run Juice Shop
docker run -d --name ctf-test-juice-shop -p 3000:3000 bkimminich/juice-shop

# Stop and remove
docker stop ctf-test-dvwa ctf-test-juice-shop
docker rm ctf-test-dvwa ctf-test-juice-shop
```

## Test Library

Shared utilities in `_lib/`:
- `TestRunner`: Base test runner class
- `TestResult`: Individual test result dataclass
- `TestSuiteResult`: Suite results with summary stats
- `ReportGenerator`: Markdown and JSON report generation

### Using the Library

```python
from tests.hands_on._lib import TestRunner, TestStatus

runner = TestRunner(tier=1, suite_name="My Tests")

# Run a test
result = runner.run_test(my_test_func, "TEST-001", "My Test")

# Print summary
runner.print_summary()
```

## Reports

Reports are automatically generated in `reports/`:
- `validation_report_YYYYMMDD_HHMMSS.md` - Markdown report
- `validation_report_YYYYMMDD_HHMMSS.json` - JSON report

### Report Contents

```markdown
# CTF Toolkit Hands-On Validation Report

## Executive Summary
| Metric | Value |
|--------|-------|
| Total Tests | 18 |
| Passed | 17 |
| Failed | 1 |
| Pass Rate | 94.4% |

## Tier Results
### Tier 1: Local Environment Tests

| Test ID | Name | Status | Duration |
|---------|------|--------|----------|
| T1-001 | Docker Image Verification | PASS | 0.12s |
| T1-002 | Database Initialization | PASS | 0.45s |
...
```

## Troubleshooting

### "Docker not found"

Install Docker Desktop for Windows or Docker Engine for Linux:
```bash
# Windows
winget install Docker.DockerDesktop

# Linux
curl -fsSL https://get.docker.com | sh
```

### "Database locked"

Close other Python processes or delete lock files:
```bash
rm -f ctf_state.db-wal ctf_state.db-shm
```

### "Internet connection failed"

Check your network connection and firewall settings. Tier 2+ require internet access to public test sites.

### "SQLMap scan times out"

This is normal for comprehensive scans. Use `--quick` flag to skip slow tests.

## File Structure

```
tests/hands_on/
├── _lib/                    # Shared test library
│   └── __init__.py          # TestRunner, TestResult, ReportGenerator
├── tier1/                   # Tier 1 tests
│   ├── t1_001_docker_images.py
│   ├── t1_002_database.py
│   ├── t1_003_sanitization.py
│   ├── t1_004_flag_detection.py
│   ├── t1_005_006_security_guards.py
│   └── t1_007_mcp_health.py
├── tier2/                   # Tier 2 tests
│   └── run_tier2.py
├── tier3/                   # Tier 3 tests
│   └── run_tier3.py
├── tier4/                   # Tier 4 tests (instructions)
│   └── run_tier4.py
├── run_tier1.py            # Tier 1 runner
├── run_tier2.py            # Tier 2 runner
├── run_tier3.py            # Tier 3 runner
├── run_tier4.py            # Tier 4 runner
├── run_all.py              # Master runner (all tiers)
└── README.md               # This file
```

## Validation Checklist

Before using CTF Toolkit in real competitions:

- [ ] Tier 1: All tests pass
- [ ] Tier 2: External target tests pass
- [ ] Tier 3: Docker vulnerable targets work
- [ ] Tier 4: Completed practice challenges
- [ ] Comfortable with tool workflow
- [ ] Database backup strategy in place

## Support

For issues or questions:
1. Check the troubleshooting section above
2. Review test output for specific error messages
3. Ensure prerequisites are met
4. Verify Docker and network connectivity

---

*Report generated automatically by CTF Toolkit Hands-On Test Suite v2.0.0*
