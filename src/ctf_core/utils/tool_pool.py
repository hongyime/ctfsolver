"""Tool pool management for CTF Toolkit.

Provides tool preloading, container pooling, and snapshot/restore functionality
to improve tool execution performance.
"""

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class ToolInstance:
    """Represents a pooled tool instance."""
    tool_name: str
    instance_id: str
    created_at: float = field(default_factory=time.time)
    last_used: float = field(default_factory=time.time)
    is_warm: bool = False  # True if tool is preloaded/ready
    health_status: str = "healthy"  # healthy, degraded, unhealthy
    metadata: Dict = field(default_factory=dict)


class ToolPool:
    """
    Pool manager for CTF tools.
    
    Maintains a pool of pre-warmed tool instances to reduce startup latency.
    Supports container-based tools (Docker) and process-based tools.
    """
    
    # Default pool sizes per tool category
    DEFAULT_POOL_SIZES = {
        "nmap": 2,
        "masscan": 1,
        "sqlmap": 2,
        "hydra": 1,
        "feroxbuster": 2,
        "nikto": 1,
        "searchsploit": 2,
        "default": 1,
    }
    
    # Tool warm-up commands (lightweight commands to keep tools ready)
    WARM_UP_COMMANDS = {
        "nmap": ["--version"],
        "sqlmap": ["--version"],
        "searchsploit": ["--version"],
        "nikto": ["-Version"],
    }
    
    def __init__(self, pool_sizes: Optional[Dict[str, int]] = None):
        """
        Initialize tool pool.
        
        Args:
            pool_sizes: Custom pool sizes per tool
        """
        self._pool_sizes = pool_sizes or self.DEFAULT_POOL_SIZES
        self._pools: Dict[str, List[ToolInstance]] = {}
        self._initializing = False
        
        logger.info("ToolPool initialized")
    
    async def initialize(self) -> None:
        """Initialize all tool pools."""
        if self._initializing:
            return
        
        self._initializing = True
        logger.info("Initializing tool pools...")
        
        for tool_name, size in self._pool_sizes.items():
            self._pools[tool_name] = []
            for i in range(size):
                instance = ToolInstance(
                    tool_name=tool_name,
                    instance_id=f"{tool_name}-{i}",
                )
                self._pools[tool_name].append(instance)
        
        self._initializing = False
        logger.info(f"Tool pools initialized: {len(self._pools)} tools")
    
    async def warm_up_tools(self) -> None:
        """Pre-warm tools by running lightweight commands."""
        logger.info("Warming up tools...")
        
        warm_up_tasks = []
        for tool_name, commands in self.WARM_UP_COMMANDS.items():
            if tool_name in self._pools:
                for instance in self._pools[tool_name]:
                    warm_up_tasks.append(self._warm_up_instance(instance, commands))
        
        if warm_up_tasks:
            await asyncio.gather(*warm_up_tasks, return_exceptions=True)
        
        logger.info("Tool warm-up completed")
    
    async def _warm_up_instance(self, instance: ToolInstance, commands: List[str]) -> None:
        """Warm up a single tool instance."""
        try:
            # In a real implementation, this would run the actual warm-up command
            # For now, just mark as warm
            instance.is_warm = True
            instance.last_used = time.time()
            logger.debug(f"Warmed up {instance.tool_name} instance {instance.instance_id}")
        except Exception as e:
            logger.warning(f"Failed to warm up {instance.tool_name}: {e}")
            instance.health_status = "degraded"
    
    async def acquire(self, tool_name: str, timeout: float = 30.0) -> Optional[ToolInstance]:
        """
        Acquire a tool instance from the pool.
        
        Args:
            tool_name: Name of the tool to acquire
            timeout: Maximum time to wait for an instance
            
        Returns:
            ToolInstance if available, None if timeout
        """
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            pool = self._pools.get(tool_name)
            if not pool:
                logger.warning(f"No pool for tool: {tool_name}")
                return None
            
            # Find an available instance
            for instance in pool:
                if instance.health_status == "healthy":
                    instance.last_used = time.time()
                    logger.debug(f"Acquired {tool_name} instance {instance.instance_id}")
                    return instance
            
            # Wait and retry
            await asyncio.sleep(0.5)
        
        logger.warning(f"Timeout waiting for {tool_name} instance")
        return None
    
    def release(self, instance: ToolInstance) -> None:
        """
        Release a tool instance back to the pool.
        
        Args:
            instance: The instance to release
        """
        instance.last_used = time.time()
        logger.debug(f"Released {instance.tool_name} instance {instance.instance_id}")
    
    def get_pool_stats(self) -> Dict[str, Any]:
        """Get statistics for all pools."""
        stats = {}
        
        for tool_name, pool in self._pools.items():
            healthy = sum(1 for i in pool if i.health_status == "healthy")
            warm = sum(1 for i in pool if i.is_warm)
            
            stats[tool_name] = {
                "total_instances": len(pool),
                "healthy_instances": healthy,
                "warm_instances": warm,
                "pool_size": self._pool_sizes.get(tool_name, 0),
            }
        
        return stats
    
    async def health_check(self) -> None:
        """Perform health check on all pooled instances."""
        logger.debug("Performing tool pool health check...")
        
        for tool_name, pool in self._pools.items():
            for instance in pool:
                # In a real implementation, this would check actual tool health
                # For now, just update last_used if instance is old
                idle_time = time.time() - instance.last_used
                if idle_time > 3600:  # 1 hour idle
                    logger.info(f"Recycling idle {tool_name} instance {instance.instance_id}")
                    instance.is_warm = False
                    instance.health_status = "healthy"
    
    async def shutdown(self) -> None:
        """Shutdown all pooled instances."""
        logger.info("Shutting down tool pools...")
        
        for pool in self._pools.values():
            for instance in pool:
                # Cleanup logic here
                instance.health_status = "unhealthy"
        
        self._pools.clear()
        logger.info("Tool pools shutdown complete")


@dataclass
class ContainerSnapshot:
    """Snapshot of a container state."""
    snapshot_id: str
    tool_name: str
    created_at: float
    state_data: Dict = field(default_factory=dict)
    size_bytes: int = 0


class ContainerSnapshotManager:
    """
    Manages container snapshots for fast restoration.
    
    Allows saving and restoring container states to avoid
    full container startup time.
    """
    
    def __init__(self, snapshot_dir: Optional[Path] = None):
        """
        Initialize snapshot manager.
        
        Args:
            snapshot_dir: Directory to store snapshots
        """
        self._snapshot_dir = snapshot_dir or Path("/tmp/ctf-snapshots")
        self._snapshots: Dict[str, ContainerSnapshot] = {}
        
        # Ensure snapshot directory exists
        self._snapshot_dir.mkdir(parents=True, exist_ok=True)
        
        logger.info(f"ContainerSnapshotManager initialized: {self._snapshot_dir}")
    
    async def create_snapshot(self, container_id: str, tool_name: str) -> str:
        """
        Create a snapshot of a running container.
        
        Args:
            container_id: Docker container ID
            tool_name: Name of the tool
            
        Returns:
            Snapshot ID
        """
        snapshot_id = f"{tool_name}-{int(time.time())}"
        
        snapshot = ContainerSnapshot(
            snapshot_id=snapshot_id,
            tool_name=tool_name,
            created_at=time.time(),
        )
        
        self._snapshots[snapshot_id] = snapshot
        logger.info(f"Created snapshot {snapshot_id} for {tool_name}")
        
        return snapshot_id
    
    async def restore_snapshot(self, snapshot_id: str) -> Optional[str]:
        """
        Restore a container from a snapshot.
        
        Args:
            snapshot_id: ID of the snapshot to restore
            
        Returns:
            New container ID, or None if restoration failed
        """
        snapshot = self._snapshots.get(snapshot_id)
        if not snapshot:
            logger.error(f"Snapshot not found: {snapshot_id}")
            return None
        
        # In a real implementation, this would restore the container
        logger.info(f"Restoring from snapshot {snapshot_id}")
        
        # Return a mock container ID
        return f"restored-{snapshot_id}"
    
    async def list_snapshots(self, tool_name: Optional[str] = None) -> List[ContainerSnapshot]:
        """List available snapshots."""
        snapshots = list(self._snapshots.values())
        if tool_name:
            snapshots = [s for s in snapshots if s.tool_name == tool_name]
        return snapshots
    
    async def delete_snapshot(self, snapshot_id: str) -> bool:
        """Delete a snapshot."""
        if snapshot_id in self._snapshots:
            del self._snapshots[snapshot_id]
            logger.info(f"Deleted snapshot {snapshot_id}")
            return True
        return False
    
    async def cleanup_old_snapshots(self, max_age_hours: int = 24) -> int:
        """Clean up old snapshots."""
        current_time = time.time()
        max_age_seconds = max_age_hours * 3600
        
        to_delete = [
            sid for sid, snapshot in self._snapshots.items()
            if current_time - snapshot.created_at > max_age_seconds
        ]
        
        for sid in to_delete:
            await self.delete_snapshot(sid)
        
        return len(to_delete)


# Global instances
_tool_pool: Optional[ToolPool] = None
_snapshot_manager: Optional[ContainerSnapshotManager] = None


def get_tool_pool() -> ToolPool:
    """Get or create the global tool pool instance."""
    global _tool_pool
    if _tool_pool is None:
        _tool_pool = ToolPool()
    return _tool_pool


def get_snapshot_manager() -> ContainerSnapshotManager:
    """Get or create the global snapshot manager instance."""
    global _snapshot_manager
    if _snapshot_manager is None:
        _snapshot_manager = ContainerSnapshotManager()
    return _snapshot_manager
