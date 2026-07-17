"""Docker execution bridge for secure tool execution with platform abstraction."""

import asyncio
import docker
import docker.errors
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from .registry import (
    derived_offline_tools as _derived_offline_tools,
    derived_tool_images as _derived_tool_images,
)
from .utils.resilience import _SHUTDOWN, _interruptible_sleep
from .utils.sanitize import sanitize_command
from .utils.sudo_guard import detect_sudo_prompt, handle_sudo_prompt
from .utils.net_guard import detect_network_failure, check_connection_allowed
from .utils.command_whitelist import SecurityLevel
from .platform import get_platform, PlatformType
from .platform.windows import WindowsAdapter
from .platform.macos import MacOSAdapter
from .platform.linux import LinuxAdapter

logger = logging.getLogger(__name__)

# Default workspace path - platform-aware
# Can be overridden via CTFTOOLKIT_WORKSPACE environment variable
if os.environ.get("CTFTOOLKIT_WORKSPACE"):
    WORKSPACE_PATH = Path(os.environ["CTFTOOLKIT_WORKSPACE"])
else:
    # Use platform adapter to get appropriate workspace path
    platform_info = get_platform()
    if platform_info.platform == PlatformType.WINDOWS:
        adapter = WindowsAdapter(is_wsl=platform_info.wsl_available)
    elif platform_info.platform == PlatformType.MACOS:
        adapter = MacOSAdapter()
    else:
        adapter = LinuxAdapter()
    WORKSPACE_PATH = Path(adapter.get_default_workspace())

TOOL_IMAGES = _derived_tool_images()

# P1-003: tools that never need network -> launched with network_disabled=True.
_OFFLINE_TOOLS = set(_derived_offline_tools())

# Heavy images that are LAZY-BUILT ONLY (never part of build-all / verify-all).
# Per UPGRADE_PLAN.md §6: SageMath is ~2.5GB and is built on first run_sage use and
# prunable when idle. Excluded from list_available_images() so a 'build all' / verify
# does not force a multi-GB Sage build on every fresh clone. Still routable via
# TOOL_IMAGES and buildable on demand (build_image / scripts/build_images.py ctf-sage).
_LAZY_ONLY_IMAGES = {"ctftoolkit/ctf-mobile", "ctftoolkit/ctf-sage"}

# Default timeout in seconds
# Default per-tool timeout in seconds (wired to CTFTOOLKIT_TIMEOUT; default 300).
DEFAULT_TIMEOUT = int(os.environ.get("CTFTOOLKIT_TIMEOUT", "300"))

# Maximum concurrent Docker containers (PRD requirement)
MAX_CONCURRENT_CONTAINERS = int(os.environ.get("CTFTOOLKIT_MAX_CONTAINERS", "5"))

# Security level to concurrency limit mapping
# Higher security = fewer concurrent containers
SECURITY_CONCURRENCY_MAP = {
    SecurityLevel.LOW: 10,
    SecurityLevel.MEDIUM: 5,
    SecurityLevel.HIGH: 3,
    SecurityLevel.PARANOID: 1,
}

# Pull retry settings for Docker images
MAX_PULL_RETRIES = 3
INITIAL_PULL_DELAY = 1  # seconds
PULL_BACKOFF_MULTIPLIER = 2

# Lazy auto-build: when a required ctftoolkit/* image is missing, build it
# from the Dockerfile at docker/<short-name>/Dockerfile on first use.
# Disable with CTFTOOLKIT_AUTO_BUILD=0.
AUTO_BUILD_IMAGES = os.environ.get("CTFTOOLKIT_AUTO_BUILD", "1").lower() not in (
    "0",
    "false",
    "no",
)
# Project root used to locate Dockerfiles for lazy builds. Computed once.
_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent

# Per-image asyncio locks so concurrent tool calls don't race on the same build.
_BUILD_LOCKS: dict[str, asyncio.Lock] = {}
_BUILD_LOCKS_GUARD = asyncio.Lock()


def _dockerfile_for(image: str) -> Optional[Path]:
    """Return the Dockerfile path for a ctftoolkit/* image, or None."""
    if not image.startswith("ctftoolkit/"):
        return None
    short = image.split("/", 1)[1]
    candidate = _PROJECT_ROOT / "docker" / short / "Dockerfile"
    return candidate if candidate.is_file() else None


class DockerRunner:
    """Executes tools in Docker containers with proper isolation and platform abstraction."""
    
    def __init__(self, workspace_path: Optional[Path] = None):
        if workspace_path is None:
            workspace_path = WORKSPACE_PATH
        self.workspace_path = workspace_path
        self.platform_info = get_platform()
        self.platform_adapter = self._get_platform_adapter()
        self.client = self._create_docker_client()
        self.workspace_path.mkdir(parents=True, exist_ok=True)
        
        # Rate limiting semaphore for concurrent container execution
        self._semaphore = asyncio.Semaphore(MAX_CONCURRENT_CONTAINERS)
        self._active_containers = 0
        
        # Track security level for dynamic concurrency adjustment
        self._security_level = SecurityLevel.MEDIUM  # Default level
        
        # Verify Docker images at startup (log warning if missing)
        self._verify_images_at_startup()
    
    def _verify_images_at_startup(self):
        """Verify required images at startup. Logs warnings for missing images."""
        try:
            success, missing = self.verify_images()
            if not success:
                logger.warning(
                    f"Missing {len(missing)} required Docker images: {missing}. "
                    f"Run 'setup.sh' to build images or they will be pulled on first use."
                )
        except Exception as e:
            logger.warning(f"Could not verify Docker images at startup: {e}")
    
    def _adjust_semaphore(self, security_level: SecurityLevel) -> None:
        """
        Adjust the container execution semaphore based on security level.
        
        Higher security = fewer concurrent containers (less resource usage, more isolation).
        Lower security = more concurrent containers (faster execution, less isolation).
        
        Args:
            security_level: The security level to adjust for
        """
        self._security_level = security_level
        new_limit = SECURITY_CONCURRENCY_MAP.get(security_level, MAX_CONCURRENT_CONTAINERS)
        
        # Create a new semaphore with the new limit
        self._semaphore = asyncio.Semaphore(new_limit)
        
        logger.info(
            f"Adjusted container concurrency for security level '{security_level.value}': "
            f"{new_limit} concurrent containers"
        )
    
    def set_security_level(self, security_level: SecurityLevel) -> None:
        """
        Set the security level and adjust container concurrency accordingly.
        
        Args:
            security_level: The new security level
        """
        self._adjust_semaphore(security_level)
    
    def get_security_level(self) -> SecurityLevel:
        """Get the current security level."""
        return self._security_level
    
    def get_concurrency_limit(self) -> int:
        """Get the current concurrency limit."""
        return SECURITY_CONCURRENCY_MAP.get(self._security_level, MAX_CONCURRENT_CONTAINERS)
    
    def _get_platform_adapter(self):
        """Get appropriate platform adapter."""
        if self.platform_info.platform == PlatformType.WINDOWS:
            return WindowsAdapter(is_wsl=self.platform_info.wsl_available)
        elif self.platform_info.platform == PlatformType.MACOS:
            return MacOSAdapter()
        else:
            return LinuxAdapter()
    
    def _create_docker_client(self) -> docker.DockerClient:
        """Create Docker client with platform-specific configuration."""
        # Get platform-specific Docker socket
        docker_socket = self.platform_info.get_docker_socket()
        
        if docker_socket:
            logger.info(f"Using Docker socket: {docker_socket}")
            return docker.DockerClient(base_url=docker_socket)
        else:
            # Fall back to default
            return docker.from_env()
    
    def _prepare_volumes(self) -> dict:
        """Prepare volume mounts with platform-specific path handling."""
        container_workspace = "/workspace"
        
        # Use platform adapter to get proper volume mount configuration
        if self.platform_info.platform == PlatformType.WINDOWS and not self.platform_info.wsl_available:
            # Windows native: need path conversion
            return self.platform_adapter.get_docker_volume_mount(
                str(self.workspace_path), 
                container_workspace, 
                "rw"
            )
        elif self.platform_info.platform == PlatformType.MACOS:
            # macOS: add platform-specific mounts
            volumes = {
                str(self.workspace_path): {"bind": container_workspace, "mode": "rw"}
            }
            # Add platform-specific mounts if available
            platform_mounts = self.platform_adapter.get_platform_specific_mounts()
            volumes.update(platform_mounts)
            return volumes
        else:
            # Linux/WSL: straightforward mounting
            volumes = {
                str(self.workspace_path): {"bind": container_workspace, "mode": "rw"}
            }
            # Add platform-specific mounts if available
            if hasattr(self.platform_adapter, 'get_platform_specific_mounts'):
                platform_mounts = self.platform_adapter.get_platform_specific_mounts()
                volumes.update(platform_mounts)
            return volumes
    
    async def run_tool(
        self,
        tool_name: str,
        args: list[str],
        timeout: int = DEFAULT_TIMEOUT,
        image: Optional[str] = None,
    ) -> dict[str, Any]:
        """
        Execute a tool in a Docker container with platform-aware handling.
        
        Args:
            tool_name: Name of the tool to execute
            args: List of command-line arguments
            timeout: Execution timeout in seconds
            image: Optional custom Docker image
            
        Returns:
            Dictionary with stdout, stderr, exit_code, and timing info
        """
        # Acquire semaphore for rate limiting
        async with self._semaphore:
            self._active_containers += 1
            logger.info(f"Container started ({self._active_containers}/{MAX_CONCURRENT_CONTAINERS})")
            
            try:
                return await self._run_tool_internal(tool_name, args, timeout, image)
            finally:
                self._active_containers -= 1
                logger.info(f"Container finished ({self._active_containers}/{MAX_CONCURRENT_CONTAINERS})")
    
    async def _run_tool_internal(
        self,
        tool_name: str,
        args: list[str],
        timeout: int = DEFAULT_TIMEOUT,
        image: Optional[str] = None,
        check_network: bool = True,
    ) -> dict[str, Any]:
        """Internal tool execution logic (called within semaphore).
        
        Args:
            check_network: If True, check network isolation policy before execution
        """
        # Validate tool and arguments
        is_safe, sanitized_binary, sanitized_args = sanitize_command(tool_name, args)
        
        # Check network isolation policy (P2-006)
        if check_network:
            # Extract target from args if present (look for IP-like patterns)
            for arg in sanitized_args:
                try:
                    allowed, reason = check_connection_allowed(arg)
                    if not allowed:
                        logger.warning(f"Network connection blocked: {reason}")
                        return {
                            "stdout": "",
                            "stderr": f"Error: {reason}",
                            "exit_code": 1,
                            "duration": 0,
                            "error": "network_blocked",
                        }
                except ValueError:
                    continue  # Not an IP address, skip check
        
        # Determine Docker image
        if image is None:
            image = TOOL_IMAGES.get(tool_name)
            if image is None:
                raise ValueError(f"No Docker image configured for tool: {tool_name}")
        
        # Verify image exists; lazy-build from local Dockerfile if missing.
        try:
            self.client.images.get(image)
        except docker.errors.NotFound:
            built = await self._ensure_image(image)
            if not built:
                logger.error(f"Required Docker image not found: {image}")
                hint = (
                    f"Run 'python scripts/build_images.py {image.split('/', 1)[-1]}' to build it, "
                    f"or set CTFTOOLKIT_AUTO_BUILD=1 to enable lazy builds."
                )
                return {
                    "stdout": "",
                    "stderr": f"Error: Docker image '{image}' not found. {hint}",
                    "exit_code": 1,
                    "duration": 0,
                    "error": "image_not_found",
                    "missing_image": image,
                }
        except docker.errors.APIError as e:
            logger.error(f"Error checking Docker image {image}: {e}")
            # Don't fail here, let the actual run attempt proceed
        
        # Build command
        cmd = [sanitized_binary] + sanitized_args

        # Prepare platform-aware volume mounts
        volumes = self._prepare_volumes()

        # Phase 2: audit the execution with secrets masked (clank mask_command).
        try:
            from .utils.audit_logger import mask_command
            masked = mask_command(" ".join(cmd))
        except Exception:
            masked = " ".join(cmd)
        logger.info(f"Running {tool_name} in Docker: {masked}")
        logger.debug(f"Platform: {self.platform_info.platform.value}, Workspace: {self.workspace_path}")
        
        start_time = datetime.now()
        
        try:
            # Prepare container configuration with platform-specific settings
            # Command injection is prevented by sanitize_command() and by passing argv list directly.
            # Identifiable name + labels so every container is attributable to this
            # toolkit (no random Docker names) and discoverable by the Phase 2
            # reconciler/pruner via `docker ps --filter label=ctftoolkit.managed=true`.
            import uuid as _uuid
            _cname = f"ctftoolkit-{tool_name}-{_uuid.uuid4().hex[:8]}"
            container_config = {
                'image': image,
                'command': cmd,
                'name': _cname,
                'labels': {
                    'ctftoolkit.managed': 'true',
                    'ctftoolkit.tool': tool_name,
                    'ctftoolkit.image': image,
                },
                'volumes': volumes,
                'remove': True,
                'detach': True,
                'network_disabled': tool_name in _OFFLINE_TOOLS,  # P1-003
                'cap_drop': ["ALL"],
                'security_opt': ["no-new-privileges:true"],
                # P1-001: drop root inside the container (override via env if a tool needs root)
                'user': os.environ.get("CTFTOOLKIT_CONTAINER_USER", "1000:1000"),
                # P1-002: resource ceilings prevent host OOM / fork-bomb from a runaway tool
                'mem_limit': os.environ.get("CTFTOOLKIT_MEM_LIMIT", "1g"),
                'pids_limit': int(os.environ.get("CTFTOOLKIT_PIDS_LIMIT", "256")),
            }
            
            # Add platform-specific configurations
            if self.platform_info.platform == PlatformType.LINUX:
                pass  # No additional Linux-specific config needed

            # Nmap needs raw socket capability for some scans even with restricted flags
            if tool_name == 'nmap':
                container_config['cap_add'] = ['NET_RAW']
            
            # Check shutdown before starting a new container
            if _SHUTDOWN.is_set():
                logger.warning("Shutdown requested - not starting new container.")
                return {
                    "stdout": "",
                    "stderr": "Shutdown requested — container not started.",
                    "exit_code": 1,
                    "duration": 0,
                    "error": "shutdown_requested",
                }

            container = self.client.containers.run(**container_config)

            try:
                # Stream logs while container runs — must be done before wait()
                # because with remove=True the container is gone after exit
                stdout_chunks = []
                timed_out = False

                try:
                    import queue as _queue
                    import threading

                    log_queue: _queue.Queue = _queue.Queue()

                    _MAX_LOG_BYTES = 10 * 1024 * 1024  # 10 MB cap
                    # No-output watchdog (Phase 2): if a container emits nothing for
                    # this many seconds it is likely blocked on stdin (interactive
                    # hang) and is killed. 0/unset disables it.
                    import time as _time_mod
                    _no_output_timeout = int(os.environ.get("CTFTOOLKIT_NO_OUTPUT_TIMEOUT", "0"))
                    _last_output = {"t": _time_mod.monotonic()}

                    def _stream_logs():
                        total = 0
                        try:
                            for chunk in container.logs(
                                stdout=True, stderr=True, stream=True, follow=True
                            ):
                                total += len(chunk)
                                _last_output["t"] = _time_mod.monotonic()
                                if total > _MAX_LOG_BYTES:
                                    log_queue.put(b"\n[LOG TRUNCATED: exceeded 10 MB cap]\n")
                                    break
                                log_queue.put(chunk)
                        except Exception as e:
                            logger.warning(f"Log stream interrupted: {e}")
                        finally:
                            log_queue.put(None)  # sentinel

                    log_thread = threading.Thread(target=_stream_logs, daemon=True)
                    log_thread.start()

                    # Wait for container with timeout, kill on Ctrl+C or timeout
                    try:
                        import time as _time
                        _deadline = _time.monotonic() + timeout
                        exit_code = None
                        while True:
                            if _SHUTDOWN.is_set():
                                logger.warning("Shutdown requested - killing running container.")
                                timed_out = True
                                exit_code = -1
                                break
                            try:
                                result = container.wait(timeout=1)
                                exit_code = result["StatusCode"]
                                break
                            except Exception:
                                now = _time.monotonic()
                                if now >= _deadline:
                                    logger.warning(f"Container exceeded timeout ({timeout}s), capturing partial output...")
                                    timed_out = True
                                    exit_code = -1
                                    break
                                # No-output watchdog: kill a silently-hung (stdin-blocked) container.
                                if (_no_output_timeout > 0
                                        and now - _last_output["t"] > _no_output_timeout):
                                    logger.warning(
                                        f"Container produced no output for {_no_output_timeout}s "
                                        f"(likely stdin-blocked); killing.")
                                    timed_out = True
                                    exit_code = -1
                                    break
                                continue
                    finally:
                        try:
                            container.kill()
                            logger.info(f"[CLEANUP] Container {container.id[:12]} killed")
                        except Exception as kill_err:
                            logger.warning(f"[CLEANUP] Failed to kill container: {kill_err}")

                    # Drain remaining log chunks (give it 2s after container exits)
                    log_thread.join(timeout=2.0)
                    while True:
                        try:
                            chunk = log_queue.get_nowait()
                            if chunk is None:
                                break
                            stdout_chunks.append(chunk)
                        except _queue.Empty:
                            break

                    stdout = b"".join(stdout_chunks).decode("utf-8", errors="replace")
                    stderr = ""

                except Exception as e:
                    logger.error(f"Failed to capture logs: {e}")
                    stdout = ""
                    stderr = f"Failed to capture container logs: {e}"

                if timed_out:
                    stderr += "\n[TIMEOUT] Container execution exceeded maximum timeout. Partial output captured above."
                
                end_time = datetime.now()
                duration = (end_time - start_time).total_seconds()
                # P5: record metrics so observability/tracing is actually exercised
                try:
                    from .observability.tracing import get_metrics
                    _m = get_metrics()
                    _m.increment_counter("tool.executions", labels={"tool": tool_name})
                    _m.record_histogram("tool.duration_ms", duration * 1000.0, labels={"tool": tool_name})
                except Exception:
                    pass
                
                # Check for sudo prompts
                if detect_sudo_prompt(stderr):
                    error_msg = handle_sudo_prompt(container)
                    return {
                        "stdout": "",
                        "stderr": error_msg,
                        "exit_code": 1,
                        "duration": duration,
                        "error": "sudo_prompt_detected",
                    }
                
                # Check for network failures
                network_error = detect_network_failure(stdout + stderr)
                
                return {
                    "stdout": stdout,
                    "stderr": stderr,
                    "exit_code": exit_code,
                    "duration": duration,
                    "network_error": network_error,
                    "timed_out": timed_out,
                }
                
            except docker.errors.APIError as e:
                logger.error(f"Docker API error: {e}")
                return {
                    "stdout": "",
                    "stderr": str(e),
                    "exit_code": 1,
                    "duration": 0,
                    "error": "docker_api_error",
                }
            finally:
                pass
                
        except Exception as e:
            logger.error(f"Error running {tool_name}: {e}")
            raise RuntimeError(f"Failed to execute {tool_name}: {e}")
    
    async def _ensure_image(self, image: str) -> bool:
        """Make sure ``image`` exists locally, building it on demand if missing.

        Lazy build only fires for images we know how to build (i.e. ones with a
        Dockerfile under ``docker/<short-name>/Dockerfile``) and only when
        ``CTFTOOLKIT_AUTO_BUILD`` is enabled (default).

        Returns True if the image is available after this call, False otherwise.
        Concurrent calls for the same image share a lock so the build runs once.
        """
        # Fast path — already present.
        try:
            self.client.images.get(image)
            return True
        except docker.errors.NotFound:
            pass
        except docker.errors.APIError as exc:
            logger.warning(f"Could not query image {image}: {exc}. Attempting build anyway.")

        if not AUTO_BUILD_IMAGES:
            logger.info(
                f"Auto-build disabled (CTFTOOLKIT_AUTO_BUILD=0); will not build {image}."
            )
            return False

        dockerfile = _dockerfile_for(image)
        if dockerfile is None:
            logger.info(
                f"No Dockerfile available for {image}; cannot lazy-build."
            )
            return False

        # Per-image lock so two concurrent tool calls don't double-build.
        async with _BUILD_LOCKS_GUARD:
            lock = _BUILD_LOCKS.setdefault(image, asyncio.Lock())

        async with lock:
            # Re-check inside the lock — a sibling call may have built it.
            try:
                self.client.images.get(image)
                return True
            except docker.errors.NotFound:
                pass

            logger.warning(
                f"Image {image} missing — building from {dockerfile.relative_to(_PROJECT_ROOT)}. "
                f"This may take several minutes on the first run."
            )
            return await asyncio.to_thread(self._build_image_sync, image, dockerfile)

    def _build_image_sync(self, image: str, dockerfile: Path) -> bool:
        """Blocking image build; called via ``asyncio.to_thread`` from the runner."""
        try:
            rel = dockerfile.relative_to(_PROJECT_ROOT).as_posix()
            logger.info(f"docker build -t {image} -f {rel} {_PROJECT_ROOT}")
            stream = self.client.api.build(
                path=str(_PROJECT_ROOT),
                dockerfile=rel,
                tag=image,
                rm=True,
                forcerm=True,
                decode=True,
            )
            for chunk in stream:
                if "stream" in chunk:
                    line = chunk["stream"].rstrip()
                    if line:
                        logger.info(f"  build[{image}]: {line}")
                elif "error" in chunk:
                    logger.error(f"  build[{image}]: {chunk['error']}")
                    return False
            # Final sanity check.
            self.client.images.get(image)
            logger.info(f"Built image {image}")
            return True
        except docker.errors.BuildError as exc:
            logger.error(f"Build failed for {image}: {exc.msg}")
            return False
        except docker.errors.APIError as exc:
            logger.error(f"Docker API error during build of {image}: {exc}")
            return False
        except Exception as exc:  # pragma: no cover — defensive
            logger.error(f"Unexpected error building {image}: {exc}")
            return False

    async def ensure_all_images(self) -> dict[str, bool]:
        """Public helper used by the ``build_images`` MCP tool.

        Returns a mapping ``{image: built_or_present}``.
        """
        results: dict[str, bool] = {}
        for image in self.list_available_images():
            results[image] = await self._ensure_image(image)
        return results

    def pull_image(self, image: str) -> bool:
        """Pull a Docker image if not already present with exponential backoff retry."""
        for attempt in range(MAX_PULL_RETRIES):
            if _SHUTDOWN.is_set():
                logger.info("Shutdown requested — aborting image pull.")
                return False
            try:
                logger.info(f"Pulling Docker image: {image} (attempt {attempt + 1}/{MAX_PULL_RETRIES})")
                self.client.images.pull(image)
                logger.info(f"Successfully pulled Docker image: {image}")
                return True
            except docker.errors.APIError as e:
                if attempt < MAX_PULL_RETRIES - 1:
                    delay = INITIAL_PULL_DELAY * (PULL_BACKOFF_MULTIPLIER ** attempt)
                    logger.warning(
                        f"Failed to pull image {image} (attempt {attempt + 1}/{MAX_PULL_RETRIES}): {e}. "
                        f"Retrying in {delay}s..."
                    )
                    _interruptible_sleep(delay)
                else:
                    logger.error(f"Failed to pull image {image} after {MAX_PULL_RETRIES} attempts: {e}")

        return False
    
    def list_available_images(self) -> list[str]:
        """List images for build-all / verify-all (excludes lazy-only heavy images)."""
        return list(set(TOOL_IMAGES.values()) - _LAZY_ONLY_IMAGES)
    
    def verify_images(self) -> tuple[bool, list[str]]:
        """
        Verify that all required Docker images are available locally.
        
        Returns:
            tuple: (success: bool, missing_images: list[str])
                   - success: True if all images are available
                   - missing_images: List of missing image names
        """
        required_images = self.list_available_images()
        missing_images = []
        
        for image in required_images:
            try:
                self.client.images.get(image)
                logger.debug(f"Image verified: {image}")
            except docker.errors.NotFound:
                logger.warning(f"Missing required image: {image}")
                missing_images.append(image)
            except docker.errors.APIError as e:
                logger.error(f"Error checking image {image}: {e}")
                missing_images.append(image)
        
        if missing_images:
            logger.error(f"Missing {len(missing_images)} required images: {missing_images}")
            return False, missing_images
        
        logger.info(f"All {len(required_images)} required images are available")
        return True, []
    
    def verify_and_pull_missing(self) -> tuple[bool, list[str]]:
        """
        Verify images and attempt to pull any missing ones with retry.
        
        Returns:
            tuple: (success: bool, failed_images: list[str])
        """
        success, missing = self.verify_images()
        
        if success:
            return True, []
        
        failed = []
        for image in missing:
            logger.info(f"Attempting to pull missing image: {image}")
            if self.pull_image(image):
                logger.info(f"Successfully pulled: {image}")
            else:
                failed.append(image)
        
        if failed:
            return False, failed
        
        # Re-verify after pulling
        return self.verify_images()

