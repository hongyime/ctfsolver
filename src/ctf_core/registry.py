"""Single declarative tool registry (Phase 3).

THE single source of truth for every tool the toolkit can run. Each ToolEntry
carries all four dimensions that previously lived in four separate places:
  * image            -> docker_runner.TOOL_IMAGES
  * offline          -> docker_runner._OFFLINE_TOOLS
  * binary           -> sanitize.ALLOWED_BINARIES
  * allowed/forbidden flags, pattern, max_args, security_level
                     -> command_whitelist ToolDefinition

`security_level` and `offline` are REQUIRED (no default) so a new tool can never
silently get a permissive gate. Dangerous binaries are rejected at construction.

This module is a LEAF: it imports only stdlib. docker_runner / sanitize /
command_whitelist import FROM it (never the reverse), so there is no import cycle.

Adding a tool = add ONE ToolEntry below.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum


class SecurityLevel(IntEnum):
    """Mirrors command_whitelist.SecurityLevel ordering (LOW< MEDIUM< HIGH< PARANOID)."""
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    PARANOID = 4


# Binaries that must NEVER be runnable as tools (shells, destructive, escalation).
# Enforced at ToolEntry construction so a dangerous binary cannot enter the registry.
DANGEROUS_BINARIES: frozenset[str] = frozenset({
    "rm", "dd", "mkfs", "mkfs.ext4", "mkfs.vfat", "shred",
    "bash", "sh", "zsh", "fish", "ksh", "csh",
    "chmod", "chown", "mount", "umount", "sudo", "su",
    "nsenter", "unshare", "setcap", "insmod", "modprobe",
    "crontab", "systemctl", "useradd", "userdel", "passwd",
})

_MISSING = object()


@dataclass(frozen=True)
class ToolEntry:
    name: str
    binary: str
    image: str
    security_level: SecurityLevel        # REQUIRED
    offline: bool                        # REQUIRED
    allowed_flags: tuple[str, ...] = ()
    forbidden_flags: tuple[str, ...] = ()
    allowed_args_pattern: str | None = None
    max_args: int = 10
    caps: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.security_level, SecurityLevel):
            raise TypeError(f"ToolEntry '{self.name}': security_level must be a SecurityLevel")
        if not isinstance(self.offline, bool):
            raise TypeError(f"ToolEntry '{self.name}': offline must be an explicit bool")
        if self.binary in DANGEROUS_BINARIES:
            raise ValueError(
                f"ToolEntry '{self.name}': binary '{self.binary}' is in the "
                f"dangerous-binary blocklist and cannot be registered.")


TOOL_REGISTRY: tuple[ToolEntry, ...] = (
    ToolEntry(
        name='ROPgadget', binary='ROPgadget', image='ctftoolkit/ctf-pwn',
        security_level=SecurityLevel.MEDIUM, offline=True,
        allowed_flags=('--binary', '--ropchain', '--depth', '--only', '--filter', '--string', '--opcode', '--memstr', '--badbytes', '--re'),
        forbidden_flags=(),
        allowed_args_pattern='^[\\w./: =+-]+$', max_args=12,
    ),
    ToolEntry(
        name='RsaCtfTool', binary='RsaCtfTool', image='ctftoolkit/ctf-crypto',
        security_level=SecurityLevel.MEDIUM, offline=True,
        allowed_flags=('--publickey', '--private', '--createpub', '--uncipher', '--cipher', '--n', '--e', '--key', '--attack', '--dumpkey', '--timeout', '--output', '--verbosity'),
        forbidden_flags=(),
        allowed_args_pattern='^[\\w./: =,-]+$', max_args=20,
    ),
    ToolEntry(
        name='amass', binary='amass', image='ctftoolkit/ctf-tools',
        security_level=SecurityLevel.MEDIUM, offline=False,
        allowed_flags=('enum', 'intel', '-d', '-passive', '-active', '-o', '-json', '-timeout', '-silent'),
        forbidden_flags=(),
        allowed_args_pattern='^[\\w./:?=&% ,-]+$', max_args=15,
    ),
    ToolEntry(
        name='assetfinder', binary='assetfinder', image='ctftoolkit/ctf-tools',
        security_level=SecurityLevel.MEDIUM, offline=False,
        allowed_flags=('--subs-only',),
        forbidden_flags=(),
        allowed_args_pattern='^[\\w./:.-]+$', max_args=4,
    ),
    ToolEntry(
        name='arjun', binary='arjun', image='ctftoolkit/ctf-tools',
        security_level=SecurityLevel.MEDIUM, offline=False,
        allowed_flags=('-u', '-m', '-oJ', '-oT', '-w', '-t', '--stable', '--headers', '--passive', '--disable-redirects'),
        forbidden_flags=(),
        allowed_args_pattern='^[\\w./:?=&% ,:@-]+$', max_args=18,
    ),
    ToolEntry(
        name='binwalk', binary='binwalk', image='ctftoolkit/ctf-re',
        security_level=SecurityLevel.MEDIUM, offline=True,
        allowed_flags=('-e', '--extract', '-B', '-A', '-M', '-D', '--dd', '-r', '--run-as', '-C', '--directory', '-q', '-y'),
        forbidden_flags=(),
        allowed_args_pattern='^[\\w./: =-]+$', max_args=10,
    ),
    ToolEntry(
        name='capa', binary='capa', image='ctftoolkit/ctf-re',
        security_level=SecurityLevel.LOW, offline=True,
        allowed_flags=('-j', '--json', '-v', '-vv', '-q', '-f', '--format', '-r', '--rules', '-s', '--signatures', '-t', '--tag'),
        forbidden_flags=(),
        allowed_args_pattern='^[\\w./: =-]+$', max_args=12,
    ),
    ToolEntry(
        name='checksec', binary='checksec', image='ctftoolkit/ctf-pwn',
        security_level=SecurityLevel.LOW, offline=True,
        allowed_flags=('--file', '--file=', '--format', '--format=', '--output', '--output=', '--proc', '--dir'),
        forbidden_flags=(),
        allowed_args_pattern='^[\\w./:= -]+$', max_args=6,
    ),
    ToolEntry(
        name='exiftool', binary='exiftool', image='ctftoolkit/ctf-forensics',
        security_level=SecurityLevel.LOW, offline=True,
        allowed_flags=('-a', '-u', '-g', '-j', '-X', '-csv', '-r', '-q'),
        forbidden_flags=('-w', '-execute'),
        allowed_args_pattern='^[\\w./: -]+$', max_args=10,
    ),
    ToolEntry(
        name='feroxbuster', binary='feroxbuster', image='ctftoolkit/ctf-tools',
        security_level=SecurityLevel.MEDIUM, offline=False,
        allowed_flags=('-u', '-w', '-t', '--threads', '-d', '--depth', '-r', '--redirects', '-x', '--extensions', '-o', '--output', '--json', '--quiet', '-k', '--insecure', '--no-recursion', '-s', '--status-codes', '--filter-status'),
        forbidden_flags=(),
        allowed_args_pattern='^[\\w./:?=&% -]+$', max_args=20,
    ),
    ToolEntry(
        name='ffuf', binary='ffuf', image='ctftoolkit/ctf-tools',
        security_level=SecurityLevel.MEDIUM, offline=False,
        allowed_flags=('-u', '-w', '-recursion', '-recursion-depth', '-maxtime', '-t', '-threads', '-H', '-X', '-b', '-mc', '-ms', '-ml', '-fw', '-fl', '-fs', '-json', '-of', '-o', '-s'),
        forbidden_flags=('-or',),
        allowed_args_pattern='^[\\w./:?=&% -]+$', max_args=20,
    ),
    ToolEntry(
        name='file', binary='file', image='ctftoolkit/ctf-re',
        security_level=SecurityLevel.LOW, offline=False,
        allowed_flags=('-b', '-i', '-z', '-k', '-L'),
        forbidden_flags=(),
        allowed_args_pattern='^[\\w./: -]+$', max_args=5,
    ),
    ToolEntry(
        name='flatter', binary='flatter', image='ctftoolkit/ctf-crypto',
        security_level=SecurityLevel.LOW, offline=True,
        allowed_flags=('-h', '-q', '-v', '-alpha', '-rhf', '-delta'),
        forbidden_flags=(),
        allowed_args_pattern='^[\\w./: =.-]+$', max_args=10,
    ),
    ToolEntry(
        name='floss', binary='floss', image='ctftoolkit/ctf-re',
        security_level=SecurityLevel.LOW, offline=True,
        allowed_flags=('-j', '--json', '-q', '-v', '-n', '--minimum-length', '--no-static', '--no-stack', '--no-tight', '--no-decoded', '-o', '--output'),
        forbidden_flags=(),
        allowed_args_pattern='^[\\w./: =-]+$', max_args=12,
    ),
    ToolEntry(
        name='foremost', binary='foremost', image='ctftoolkit/ctf-forensics',
        security_level=SecurityLevel.LOW, offline=False,
        allowed_flags=('-i', '-o', '-t', '-T', '-v', '-q', '-Q', '-c'),
        forbidden_flags=(),
        allowed_args_pattern='^[\\w./:= ,-]+$', max_args=10,
    ),
    ToolEntry(
        name='gdb', binary='gdb', image='ctftoolkit/ctf-pwn',
        security_level=SecurityLevel.MEDIUM, offline=False,
        allowed_flags=('-batch', '-x', '-q', '-nx', '--nx', '--batch'),
        forbidden_flags=('-p', '--pid', '-ex'),
        allowed_args_pattern='^[\\w./: -]+$', max_args=8,
    ),
    ToolEntry(
        name='gdbserver', binary='gdbserver', image='ctftoolkit/ctf-pwn',
        security_level=SecurityLevel.MEDIUM, offline=False,
        allowed_flags=('--once', '--multi', '--attach'),
        forbidden_flags=(),
        allowed_args_pattern='^[\\w./:= -]+$', max_args=8,
    ),
    ToolEntry(
        name='ghidra', binary='ghidra', image='ctftoolkit/ctf-re',
        security_level=SecurityLevel.MEDIUM, offline=True,
        allowed_flags=('-import', '-process', '-postScript', '-preScript', '-scriptPath', '-deleteProject', '-readOnly', '-noanalysis', '-overwrite', '-recursive'),
        forbidden_flags=(),
        allowed_args_pattern='^[\\w./: =-]+$', max_args=20,
    ),
    ToolEntry(
        name='gobuster', binary='gobuster', image='ctftoolkit/ctf-tools',
        security_level=SecurityLevel.MEDIUM, offline=False,
        allowed_flags=('dir', 'dns', 'vhost', '-u', '-w', '-t', '-threads', '-k', '-r', '-z', '-e', '-k', '-x', '-s', '-b', '-l', '-m'),
        forbidden_flags=(),
        allowed_args_pattern='^[\\w./:?=&% -]+$', max_args=15,
    ),
    ToolEntry(
        name='hashcat', binary='hashcat', image='ctftoolkit/ctf-crypto',
        security_level=SecurityLevel.MEDIUM, offline=True,
        allowed_flags=('-m', '-a', '-o', '-d', '--opencl-device-types', '-w', '--workload-profile', '-t', '--kernel-accel', '--force', '--quiet', '--status', '--status-timer'),
        forbidden_flags=('--backend-info',),
        allowed_args_pattern='^[\\w./: -]+$', max_args=20,
    ),
    ToolEntry(
        name='apktool', binary='apktool', image='ctftoolkit/ctf-mobile',
        security_level=SecurityLevel.MEDIUM, offline=True,
        allowed_flags=('d', 'decode', 'b', 'build', '-f', '--force', '-o', '--output', '-r', '--no-res', '-s', '--no-src', '--only-main-classes', '-q'),
        forbidden_flags=(),
        allowed_args_pattern='^[\\w./: =-]+$', max_args=14,
    ),
    ToolEntry(
        name='jadx', binary='jadx', image='ctftoolkit/ctf-mobile',
        security_level=SecurityLevel.MEDIUM, offline=True,
        allowed_flags=('-d', '--output-dir', '--show-bad-code', '--deobf', '--deobf-min', '--deobf-max', '--no-res', '--no-src', '--threads-count', '--log-level'),
        forbidden_flags=(),
        allowed_args_pattern='^[\\w./: =-]+$', max_args=14,
    ),
    ToolEntry(
        name='ilspycmd', binary='ilspycmd', image='ctftoolkit/ctf-mobile',
        security_level=SecurityLevel.MEDIUM, offline=True,
        allowed_flags=('-o', '--outputdir', '-p', '--project', '-t', '--type', '-il', '--ilcode', '--no-dead-code', '--no-dead-stores', '--nested-directories'),
        forbidden_flags=(),
        allowed_args_pattern='^[\\w./: =.-]+$', max_args=14,
    ),
    ToolEntry(
        name='httpx', binary='httpx', image='ctftoolkit/ctf-tools',
        security_level=SecurityLevel.MEDIUM, offline=False,
        allowed_flags=('-u', '-l', '-status-code', '-sc', '-title', '-tech-detect', '-td', '-json', '-silent', '-t', '-threads', '-timeout', '-o', '-ip'),
        forbidden_flags=(),
        allowed_args_pattern='^[\\w./:?=&% ,-]+$', max_args=20,
    ),
    ToolEntry(
        name='git-dumper', binary='git-dumper', image='ctftoolkit/ctf-tools',
        security_level=SecurityLevel.MEDIUM, offline=False,
        allowed_flags=('--jobs', '--retry', '--timeout', '--proxy', '--user-agent'),
        forbidden_flags=(),
        allowed_args_pattern='^[\\w./:?=&% ,:@-]+$', max_args=12,
    ),
    ToolEntry(
        name='gitleaks', binary='gitleaks', image='ctftoolkit/ctf-tools',
        security_level=SecurityLevel.MEDIUM, offline=True,
        allowed_flags=('detect', 'dir', '--source', '--report-format', '--report-path', '--no-git', '--redact', '--verbose'),
        forbidden_flags=(),
        allowed_args_pattern='^[\\w./: =.-]+$', max_args=14,
    ),
    ToolEntry(
        name='graphql-cop', binary='graphql-cop', image='ctftoolkit/ctf-tools',
        security_level=SecurityLevel.MEDIUM, offline=False,
        allowed_flags=('-t', '--target', '-H', '--header', '--json', '--proxy'),
        forbidden_flags=(),
        allowed_args_pattern='^[\\w./:?=&% ,:@-]+$', max_args=16,
    ),
    ToolEntry(
        name='hydra', binary='hydra', image='ctftoolkit/ctf-tools',
        security_level=SecurityLevel.HIGH, offline=False,
        allowed_flags=('-l', '-L', '-p', '-P', '-f', '-F', '-t', '-tasks', '-w', '-W', '-b', '-V', '-v', '-d', 'ssh', 'ftp', 'http', 'https', 'smb', 'rdp', 'smtp', 'pop3'),
        forbidden_flags=('-C',),
        allowed_args_pattern='^[\\w./:@ -]+$', max_args=20,
    ),
    ToolEntry(
        name='john', binary='john', image='ctftoolkit/ctf-crypto',
        security_level=SecurityLevel.MEDIUM, offline=True,
        allowed_flags=('--wordlist', '--rules', '--format', '--fork', '--pot', '--session', '--show', '--format'),
        forbidden_flags=('--stdin',),
        allowed_args_pattern='^[\\w./: -]+$', max_args=15,
    ),
    ToolEntry(
        name='jwt_tool', binary='jwt_tool', image='ctftoolkit/ctf-tools',
        security_level=SecurityLevel.MEDIUM, offline=False,
        allowed_flags=('-t', '-rh', '-rc', '-d', '-C', '-X', '-I', '-S', '-pc', '-pv', '-T', '-Q', '-b', '-mode', '-V'),
        forbidden_flags=(),
        allowed_args_pattern='^[\\w./:?=&%,. @+-]+$', max_args=20,
    ),
    ToolEntry(
        name='katana', binary='katana', image='ctftoolkit/ctf-tools',
        security_level=SecurityLevel.MEDIUM, offline=False,
        allowed_flags=('-u', '-list', '-d', '-jc', '-kf', '-fx', '-json', '-silent', '-o', '-rate-limit', '-timeout', '-retries', '-headers'),
        forbidden_flags=(),
        allowed_args_pattern='^[\\w./:?=&% ,:@-]+$', max_args=20,
    ),
    ToolEntry(
        name='linkfinder', binary='linkfinder', image='ctftoolkit/ctf-tools',
        security_level=SecurityLevel.MEDIUM, offline=False,
        allowed_flags=('-i', '-o', '-r', '-d'),
        forbidden_flags=(),
        allowed_args_pattern='^[\\w./:?=&% ,:@-]+$', max_args=10,
    ),
    ToolEntry(
        name='masscan', binary='masscan', image='ctftoolkit/ctf-tools',
        security_level=SecurityLevel.MEDIUM, offline=False,
        allowed_flags=('-p', '-r', '--rate', '--banners', '-oL', '-oX', '-oG', '--exclude', '--excludefile'),
        forbidden_flags=('-e', '--adapter'),
        allowed_args_pattern='^[\\w./: -]+$', max_args=10,
    ),
    ToolEntry(
        name='nikto', binary='nikto', image='ctftoolkit/ctf-tools',
        security_level=SecurityLevel.MEDIUM, offline=False,
        allowed_flags=('-h', '-p', '-ssl', '-Cgidirs', '-Format', '-display', '-ask', '-Tuning'),
        forbidden_flags=('-evasion',),
        allowed_args_pattern='^[\\w./: -]+$', max_args=15,
    ),
    ToolEntry(
        name='nm', binary='nm', image='ctftoolkit/ctf-re',
        security_level=SecurityLevel.LOW, offline=False,
        allowed_flags=('-C', '-D', '-g', '-u', '-a', '--defined-only'),
        forbidden_flags=(),
        allowed_args_pattern='^[\\w./: -]+$', max_args=5,
    ),
    ToolEntry(
        name='nmap', binary='nmap', image='ctftoolkit/ctf-tools',
        security_level=SecurityLevel.MEDIUM, offline=False,
        allowed_flags=('-sS', '-sT', '-sU', '-sV', '-sC', '-O', '-A', '-p', '-Pn', '-sn', '-F', '-r', '--top-ports', '-oN', '-oX', '-oG', '-oA', '--min-rate', '--max-rate', '--open', '--exclude'),
        forbidden_flags=('-e', '--script-args', '-S', '-D', '-g', '--spoof-mac', '--source-port', '--proxies'),
        allowed_args_pattern='^[\\w./: -]+$', max_args=20,
    ),
    ToolEntry(
        name='nuclei', binary='nuclei', image='ctftoolkit/ctf-tools',
        security_level=SecurityLevel.MEDIUM, offline=False,
        allowed_flags=('-u', '-l', '-t', '-tags', '-severity', '-json', '-jsonl', '-o', '-silent', '-rl', '-c', '-timeout', '-retries', '-no-color', '-nc'),
        forbidden_flags=('-i', '-interactsh-server'),
        allowed_args_pattern='^[\\w./:?=&%, -]+$', max_args=20,
    ),
    ToolEntry(
        name='objdump', binary='objdump', image='ctftoolkit/ctf-re',
        security_level=SecurityLevel.LOW, offline=True,
        allowed_flags=('-d', '-D', '-x', '-h', '-t', '-T', '-s', '-f', '-M', 'intel'),
        forbidden_flags=(),
        allowed_args_pattern='^[\\w./: =-]+$', max_args=8,
    ),
    ToolEntry(
        name='one_gadget', binary='one_gadget', image='ctftoolkit/ctf-pwn',
        security_level=SecurityLevel.LOW, offline=True,
        allowed_flags=('-b', '--build-id', '-l', '--level', '-f', '--force-file', '-n', '--near', '--raw', '--script'),
        forbidden_flags=(),
        allowed_args_pattern='^[\\w./: =-]+$', max_args=10,
    ),
    ToolEntry(
        name='openssl', binary='openssl', image='ctftoolkit/ctf-crypto',
        security_level=SecurityLevel.LOW, offline=True,
        allowed_flags=('enc', 'dgst', 'rsa', 'x509', 'req', 'genrsa', 'rsautl', 'pkey', 'asn1parse', 's_client', 'base64', '-in', '-out', '-d', '-e', '-a', '-A', '-text', '-noout', '-pubin', '-inform', '-outform', '-modulus', '-md5', '-sha1', '-sha256', '-k', '-K', '-iv', '-nosalt', '-salt', '-pass', '-decrypt', '-encrypt'),
        forbidden_flags=(),
        allowed_args_pattern='^[\\w./:= +-]+$', max_args=20,
    ),
    ToolEntry(
        name='patchelf', binary='patchelf', image='ctftoolkit/ctf-pwn',
        security_level=SecurityLevel.MEDIUM, offline=True,
        allowed_flags=('--set-interpreter', '--set-rpath', '--add-rpath', '--replace-needed', '--add-needed', '--print-interpreter', '--print-rpath', '--print-needed', '--output'),
        forbidden_flags=(),
        allowed_args_pattern='^[\\w./: =-]+$', max_args=12,
    ),
    ToolEntry(
        name='pwninit', binary='pwninit', image='ctftoolkit/ctf-pwn',
        security_level=SecurityLevel.MEDIUM, offline=True,
        allowed_flags=('--bin', '--libc', '--ld', '--no-patch', '--template-output'),
        forbidden_flags=(),
        allowed_args_pattern='^[\\w./: =-]+$', max_args=10,
    ),
    ToolEntry(
        name='pwntools', binary='pwntools', image='ctftoolkit/ctf-pwn',
        security_level=SecurityLevel.MEDIUM, offline=False,
        allowed_flags=(),
        forbidden_flags=('-c', '-m'),
        allowed_args_pattern='^[\\w./: -]+$', max_args=4,
    ),
    ToolEntry(
        name='python3', binary='python3', image='ctftoolkit/ctf-crypto',
        security_level=SecurityLevel.MEDIUM, offline=False,
        allowed_flags=(),
        forbidden_flags=('-c', '-m'),
        allowed_args_pattern='^[\\w./: -]+$', max_args=4,
    ),
    ToolEntry(
        name='pyinstxtractor', binary='pyinstxtractor', image='ctftoolkit/ctf-mobile',
        security_level=SecurityLevel.MEDIUM, offline=True,
        allowed_flags=(),
        forbidden_flags=('-c', '-m'),
        allowed_args_pattern='^[\\w./: -]+$', max_args=4,
    ),
    ToolEntry(
        name='r2', binary='r2', image='ctftoolkit/ctf-pwn',
        security_level=SecurityLevel.MEDIUM, offline=True,
        allowed_flags=('-A', '-a', '-b', '-c', '-i', '-q', '-qq', '-e', '-n', '-w'),
        forbidden_flags=(),
        allowed_args_pattern='^[\\w./:= -]+$', max_args=12,
    ),
    ToolEntry(
        name='radare2', binary='radare2', image='ctftoolkit/ctf-pwn',
        security_level=SecurityLevel.MEDIUM, offline=True,
        allowed_flags=('-A', '-a', '-b', '-c', '-i', '-q', '-qq', '-e', '-n', '-w'),
        forbidden_flags=(),
        allowed_args_pattern='^[\\w./:= -]+$', max_args=12,
    ),
    ToolEntry(
        name='readelf', binary='readelf', image='ctftoolkit/ctf-re',
        security_level=SecurityLevel.LOW, offline=False,
        allowed_flags=('-h', '-l', '-S', '-s', '-d', '-r', '-a', '-x', '-p', '-W', '--dyn-syms'),
        forbidden_flags=(),
        allowed_args_pattern='^[\\w./: =-]+$', max_args=8,
    ),
    ToolEntry(
        name='rizin', binary='rizin', image='ctftoolkit/ctf-re',
        security_level=SecurityLevel.MEDIUM, offline=True,
        allowed_flags=('-A', '-a', '-b', '-c', '-i', '-q', '-qq', '-e', '-n', '-w'),
        forbidden_flags=(),
        allowed_args_pattern='^[\\w./:= -]+$', max_args=12,
    ),
    ToolEntry(
        name='ropgadget', binary='ropgadget', image='ctftoolkit/ctf-pwn',
        security_level=SecurityLevel.MEDIUM, offline=True,
        allowed_flags=('--binary', '--ropchain', '--depth', '--only', '--filter', '--string', '--opcode', '--memstr', '--badbytes', '--re'),
        forbidden_flags=(),
        allowed_args_pattern='^[\\w./: =+-]+$', max_args=12,
    ),
    ToolEntry(
        name='rz-bin', binary='rz-bin', image='ctftoolkit/ctf-re',
        security_level=SecurityLevel.LOW, offline=True,
        allowed_flags=('-I', '-e', '-i', '-s', '-S', '-z', '-zz', '-R', '-l', '-j', '-q'),
        forbidden_flags=(),
        allowed_args_pattern='^[\\w./:= -]+$', max_args=10,
    ),
    ToolEntry(
        name='sage', binary='sage', image='ctftoolkit/ctf-sage',
        security_level=SecurityLevel.MEDIUM, offline=True,
        allowed_flags=(),
        forbidden_flags=('-c', '--command', '-python', '--python'),
        allowed_args_pattern='^[\\w./: -]+$', max_args=4,
    ),
    ToolEntry(
        name='searchsploit', binary='searchsploit', image='ctftoolkit/ctf-tools',
        security_level=SecurityLevel.LOW, offline=True,
        allowed_flags=('-c', '-t', '-p', '-w', '--colour', '--nmap', '-v', '-j'),
        forbidden_flags=('-x',),
        allowed_args_pattern='^[\\w./: -]+$', max_args=10,
    ),
    ToolEntry(
        name='schemathesis', binary='schemathesis', image='ctftoolkit/ctf-tools',
        security_level=SecurityLevel.MEDIUM, offline=False,
        allowed_flags=('run', '--base-url', '--checks', '--hypothesis-max-examples', '--header', '--auth', '--method', '--endpoint', '--report', '--junit-xml', '--workers'),
        forbidden_flags=(),
        allowed_args_pattern='^[\\w./:?=&% ,:@-]+$', max_args=24,
    ),
    ToolEntry(
        name='seccomp-tools', binary='seccomp-tools', image='ctftoolkit/ctf-pwn',
        security_level=SecurityLevel.MEDIUM, offline=True,
        allowed_flags=('dump', 'asm', 'disasm', 'emu', '-f', '--format', '-c', '--limit'),
        forbidden_flags=(),
        allowed_args_pattern='^[\\w./: =-]+$', max_args=10,
    ),
    ToolEntry(
        name='socat', binary='socat', image='ctftoolkit/ctf-pwn',
        security_level=SecurityLevel.MEDIUM, offline=False,
        allowed_flags=('-', '-d', '-dd', '-v', '-x', '-t', '-T', '-b'),
        forbidden_flags=('EXEC', 'SYSTEM', 'exec', 'system'),
        allowed_args_pattern='^[\\w./:=,@ -]+$', max_args=10,
    ),
    ToolEntry(
        name='sox', binary='sox', image='ctftoolkit/ctf-forensics',
        security_level=SecurityLevel.LOW, offline=True,
        allowed_flags=('-n', '-t', '-r', '-b', '-c', 'spectrogram', '-o', 'stat', 'stats', 'remix', 'trim', 'channels'),
        forbidden_flags=(),
        allowed_args_pattern='^[\\w./: =:.-]+$', max_args=20,
    ),
    ToolEntry(
        name='spiderfoot', binary='spiderfoot', image='ctftoolkit/ctf-tools',
        security_level=SecurityLevel.MEDIUM, offline=False,
        allowed_flags=('-s', '-m', '-t', '-F', '-o', '-n', '-q', '-l'),
        forbidden_flags=(),
        allowed_args_pattern='^[\\w./:?=&% ,_-]+$', max_args=15,
    ),
    ToolEntry(
        name='sqlmap', binary='sqlmap', image='ctftoolkit/ctf-tools',
        security_level=SecurityLevel.MEDIUM, offline=False,
        allowed_flags=('-u', '--url', '-d', '--dbms', '--batch', '--level', '--risk', '--dbs', '--tables', '--columns', '--dump', '--count', '-p', '--data', '--cookie', '--user-agent', '--tamper'),
        forbidden_flags=('--os-shell', '--os-pwn', '--os-bof'),
        allowed_args_pattern='^[\\w./:?=&% -]+$', max_args=30,
    ),
    ToolEntry(
        name='steghide', binary='steghide', image='ctftoolkit/ctf-forensics',
        security_level=SecurityLevel.LOW, offline=False,
        allowed_flags=('-sf', '-xf', '-cf', '-ef', '-p', '-v'),
        forbidden_flags=(),
        allowed_args_pattern='^[\\w./: @=+-]+$', max_args=10,
    ),
    ToolEntry(
        name='stegseek', binary='stegseek', image='ctftoolkit/ctf-forensics',
        security_level=SecurityLevel.LOW, offline=True,
        allowed_flags=('-sf', '-wl', '-xf', '-f', '--crack', '--seed', '-q', '-v'),
        forbidden_flags=(),
        allowed_args_pattern='^[\\w./: =-]+$', max_args=10,
    ),
    ToolEntry(
        name='strings', binary='strings', image='ctftoolkit/ctf-re',
        security_level=SecurityLevel.LOW, offline=True,
        allowed_flags=('-n', '-a', '-t', '-e', '-f'),
        forbidden_flags=(),
        allowed_args_pattern='^[\\w./: -]+$', max_args=8,
    ),
    ToolEntry(
        name='theHarvester', binary='theHarvester', image='ctftoolkit/ctf-tools',
        security_level=SecurityLevel.MEDIUM, offline=False,
        allowed_flags=('-d', '-b', '-f', '-l', '-s', '-g', '-n'),
        forbidden_flags=(),
        allowed_args_pattern='^[\\w./:?=&% ,_-]+$', max_args=15,
    ),
    ToolEntry(
        name='tshark', binary='tshark', image='ctftoolkit/ctf-forensics',
        security_level=SecurityLevel.MEDIUM, offline=False,
        allowed_flags=('-r', '-Y', '-T', '-e', '-V', '-x', '-c', '-q', '-z', '-n', '-O', '-d', '--export-objects'),
        forbidden_flags=('-i', '-w'),
        allowed_args_pattern='^[\\w./:= ,.|()\\"-]+$', max_args=20,
    ),
    ToolEntry(
        name='capinfos', binary='capinfos', image='ctftoolkit/ctf-forensics',
        security_level=SecurityLevel.LOW, offline=True,
        allowed_flags=('-a', '-c', '-d', '-e', '-E', '-H', '-i', '-k', '-l', '-M', '-S', '-T'),
        forbidden_flags=(),
        allowed_args_pattern='^[\\w./: -]+$', max_args=8,
    ),
    ToolEntry(
        name='usb_hid_extract', binary='usb_hid_extract', image='ctftoolkit/ctf-forensics',
        security_level=SecurityLevel.LOW, offline=True,
        allowed_flags=('--mode',),
        forbidden_flags=(),
        allowed_args_pattern='^[\\w./: =-]+$', max_args=6,
    ),
    ToolEntry(
        name='volatility', binary='volatility', image='ctftoolkit/ctf-forensics',
        security_level=SecurityLevel.MEDIUM, offline=True,
        allowed_flags=('-f', '--file', 'imageinfo', 'pslist', 'pstree', 'netscan', 'filescan', 'dumpfiles', 'dumpfuncs'),
        forbidden_flags=(),
        allowed_args_pattern='^[\\w./: -]+$', max_args=15,
    ),
    ToolEntry(
        name='wasm2wat', binary='wasm2wat', image='ctftoolkit/ctf-re',
        security_level=SecurityLevel.LOW, offline=True,
        allowed_flags=('-o', '--output', '-v', '--enable-all', '--no-check'),
        forbidden_flags=(),
        allowed_args_pattern='^[\\w./: =-]+$', max_args=8,
    ),
    ToolEntry(
        name='wat2wasm', binary='wat2wasm', image='ctftoolkit/ctf-re',
        security_level=SecurityLevel.LOW, offline=True,
        allowed_flags=('-o', '--output', '-v', '--enable-all', '--no-check'),
        forbidden_flags=(),
        allowed_args_pattern='^[\\w./: =-]+$', max_args=8,
    ),
    ToolEntry(
        name='wfuzz', binary='wfuzz', image='ctftoolkit/ctf-tools',
        security_level=SecurityLevel.MEDIUM, offline=False,
        allowed_flags=('-w', '-u', '-z', '-d', '-H', '-b', '--hc', '--hl', '--hw', '--hh', '-t', '-o'),
        forbidden_flags=(),
        allowed_args_pattern='^[\\w./:?=&%@ ,-]+$', max_args=20,
    ),
    ToolEntry(
        name='whatweb', binary='whatweb', image='ctftoolkit/ctf-tools',
        security_level=SecurityLevel.MEDIUM, offline=False,
        allowed_flags=('-a', '--aggression', '-v', '--verbose', '--color', '--no-errors', '-u', '--user-agent', '--log-json', '--log-brief', '-t', '--max-threads'),
        forbidden_flags=(),
        allowed_args_pattern='^[\\w./:?=&% ,_-]+$', max_args=15,
    ),
    ToolEntry(
        name='zsteg', binary='zsteg', image='ctftoolkit/ctf-forensics',
        security_level=SecurityLevel.LOW, offline=True,
        allowed_flags=('-a', '--all', '-E', '--extract', '-v', '--verbose', '-l', '--limit', '-b', '--bits', '--lsb', '--msb'),
        forbidden_flags=(),
        allowed_args_pattern='^[\\w./: =,-]+$', max_args=12,
    ),
)


# ── Derived views (computed once at import) ──────────────────────────────────
def _build():
    images: dict[str, str] = {}
    offline: set[str] = set()
    binaries: set[str] = set()
    for e in TOOL_REGISTRY:
        if e.image:
            images[e.name] = e.image
            images[e.binary] = e.image  # tools are invoked by binary name via run_tool
        binaries.add(e.binary)
        if e.offline:
            offline.add(e.binary)
            offline.add(e.name)
    return images, frozenset(offline), frozenset(binaries)


_IMAGES, _OFFLINE, _BINARIES = _build()


def derived_tool_images() -> dict[str, str]:
    """{tool_or_binary_name: image} for docker_runner.TOOL_IMAGES."""
    return dict(_IMAGES)


def derived_offline_tools() -> frozenset[str]:
    """Names/binaries launched with network_disabled=True."""
    return _OFFLINE


def derived_allowed_binaries() -> frozenset[str]:
    """Binary names permitted by the layer-1 gate (sanitize.ALLOWED_BINARIES)."""
    return _BINARIES


def entries_by_name() -> dict[str, ToolEntry]:
    return {e.name: e for e in TOOL_REGISTRY}
