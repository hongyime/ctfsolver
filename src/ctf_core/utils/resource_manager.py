"""Resource monitoring and dynamic allocation for CTF Toolkit.

Provides system resource monitoring, dynamic concurrency limits, and priority-based
task scheduling to optimize performance and prevent resource exhaustion.
"""

import asyncio
import logging
import os
import psutil
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Callable, Awaitable
from collections import defaultdict

logger = logging.getLogger(__name__)


class ResourceLevel(Enum):
    """Resource availability levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class SystemResources:
    """Current system resource status."""
    cpu_percent: float
    memory_percent: float
    memory_available_mb: float
    disk_percent: float
    network_connections: int
    timestamp: float = field(default_factory=time.time)
    
    @property
    def level(self) -> ResourceLevel:
        """Determine resource availability level."""
        if self.cpu_percent > 90 or self.memory_percent > 90:
            return ResourceLevel.CRITICAL
        elif self.cpu_percent > 70 or self.memory_percent > 70:
            return ResourceLevel.LOW
        elif self.cpu_percent > 40 or self.memory_percent > 40:
            return ResourceLevel.MEDIUM
        else:
            return ResourceLevel.HIGH


@dataclass
class TaskPriority:
    """Task priority levels."""
    LOW = 0
    NORMAL = 1
    HIGH = 2
    CRITICAL = 3


@dataclass
class QueuedTask:
    """A task waiting in the priority queue."""
    task_id: str
    tool_name: str
    priority: int
    enqueue_time: float
    target_id: Optional[int] = None
    estimated_duration: float = 30.0  # seconds
    callback: Optional[Callable] = None


class ResourceManager:
    """
    Central resource manager for CTF Toolkit.
    
    Monitors system resources and dynamically adjusts concurrency limits
    to prevent resource exhaustion while maximizing throughput.
    """
    
    # Resource thresholds
    CPU_HIGH_THRESHOLD = 80.0
    CPU_CRITICAL_THRESHOLD = 95.0
    MEMORY_HIGH_THRESHOLD = 80.0
    MEMORY_CRITICAL_THRESHOLD = 95.0
    
    # Concurrency settings
    MIN_CONCURRENCY = 1
    MAX_CONCURRENCY = 10
    DEFAULT_CONCURRENCY = 3
    
    def __init__(self):
        """Initialize resource manager."""
        self._running_tasks: Dict[str, TaskInfo] = {}
        self._task_queue: List[QueuedTask] = []
        self._resource_history: List[SystemResources] = []
        self._current_concurrency = self.DEFAULT_CONCURRENCY
        self._monitor_task: Optional[asyncio.Task] = None
        self._running = False
        
        # Per-tool limits
        self._tool_limits: Dict[str, int] = {
            "nmap": 2,
            "masscan": 1,
            "sqlmap": 2,
            "hydra": 1,
            "feroxbuster": 2,
            "nikto": 2,
            "default": 3,
        }
        
        logger.info("ResourceManager initialized")
    
    async def start_monitoring(self, interval: float = 5.0) -> None:
        """Start background resource monitoring."""
        self._running = True
        self._monitor_task = asyncio.create_task(
            self._monitor_loop(interval)
        )
        logger.info("Resource monitoring started")
    
    async def stop_monitoring(self) -> None:
        """Stop background resource monitoring."""
        self._running = False
        if self._monitor_task:
            self._monitor_task.cancel()
            try:
                await self._monitor_task
            except asyncio.CancelledError:
                pass
        logger.info("Resource monitoring stopped")
    
    async def _monitor_loop(self, interval: float) -> None:
        """Background monitoring loop."""
        while self._running:
            try:
                resources = self._sample_resources()
                self._resource_history.append(resources)
                
                # Keep only last 100 samples
                if len(self._resource_history) > 100:
                    self._resource_history = self._resource_history[-100:]
                
                # Adjust concurrency based on resources
                self._adjust_concurrency(resources)
                
                # Process task queue
                await self._process_queue()
                
            except Exception as e:
                logger.error(f"Error in monitor loop: {e}")
            
            await asyncio.sleep(interval)
    
    def _sample_resources(self) -> SystemResources:
        """Sample current system resources."""
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        
        # Count network connections
        try:
            connections = len(psutil.net_connections())
        except (psutil.AccessDenied, PermissionError):
            connections = 0
        
        return SystemResources(
            cpu_percent=psutil.cpu_percent(interval=0.1),
            memory_percent=memory.percent,
            memory_available_mb=memory.available / (1024 * 1024),
            disk_percent=disk.percent,
            network_connections=connections,
        )
    
    def _adjust_concurrency(self, resources: SystemResources) -> None:
        """Adjust concurrency limit based on resource availability."""
        level = resources.level
        
        if level == ResourceLevel.CRITICAL:
            new_concurrency = self.MIN_CONCURRENCY
        elif level == ResourceLevel.LOW:
            new_concurrency = max(self.MIN_CONCURRENCY, self._current_concurrency - 1)
        elif level == ResourceLevel.MEDIUM:
            new_concurrency = min(self.MAX_CONCURRENCY, self._current_concurrency + 1)
        else:  # HIGH
            new_concurrency = self.MAX_CONCURRENCY
        
        if new_concurrency != self._current_concurrency:
            logger.info(f"Adjusting concurrency: {self._current_concurrency} -> {new_concurrency}")
            self._current_concurrency = new_concurrency
    
    async def submit_task(
        self,
        task_id: str,
        tool_name: str,
        coro: Awaitable,
        priority: int = TaskPriority.NORMAL,
        target_id: Optional[int] = None,
        estimated_duration: float = 30.0,
    ) -> str:
        """
        Submit a task for execution.
        
        Args:
            task_id: Unique task identifier
            tool_name: Name of the tool being executed
            coro: Async coroutine to execute
            priority: Task priority level
            target_id: Optional target ID
            estimated_duration: Estimated execution time in seconds
            
        Returns:
            Task ID
        """
        # Check tool-specific limits
        tool_limit = self._tool_limits.get(tool_name, self._tool_limits["default"])
        running_tool_tasks = sum(
            1 for task in self._running_tasks.values() 
            if task.tool_name == tool_name
        )
        
        if running_tool_tasks >= tool_limit:
            # Queue the task
            task = QueuedTask(
                task_id=task_id,
                tool_name=tool_name,
                priority=priority,
                enqueue_time=time.time(),
                target_id=target_id,
                estimated_duration=estimated_duration,
            )
            self._task_queue.append(task)
            # Sort by priority (higher first) then by enqueue time
            self._task_queue.sort(key=lambda t: (-t.priority, t.enqueue_time))
            logger.info(f"Task {task_id} queued (tool limit reached: {tool_limit})")
            return task_id
        
        # Check overall concurrency
        if len(self._running_tasks) >= self._current_concurrency:
            # Queue the task
            task = QueuedTask(
                task_id=task_id,
                tool_name=tool_name,
                priority=priority,
                enqueue_time=time.time(),
                target_id=target_id,
                estimated_duration=estimated_duration,
            )
            self._task_queue.append(task)
            self._task_queue.sort(key=lambda t: (-t.priority, t.enqueue_time))
            logger.info(f"Task {task_id} queued (concurrency limit: {self._current_concurrency})")
            return task_id
        
        # Execute immediately
        asyncio.create_task(self._execute_task(task_id, tool_name, coro))
        return task_id
    
    async def _execute_task(self, task_id: str, tool_name: str, coro: Awaitable) -> None:
        """Execute a task and track its lifecycle."""
        task_info = TaskInfo(
            task_id=task_id,
            tool_name=tool_name,
            start_time=time.time(),
        )
        self._running_tasks[task_id] = task_info
        
        try:
            result = await coro
            task_info.success = True
            task_info.end_time = time.time()
            logger.info(f"Task {task_id} completed successfully")
        except Exception as e:
            task_info.success = False
            task_info.end_time = time.time()
            task_info.error = str(e)
            logger.error(f"Task {task_id} failed: {e}")
        finally:
            del self._running_tasks[task_id]
            # Process next queued task
            await self._process_queue()
    
    async def _process_queue(self) -> None:
        """Process queued tasks if capacity available."""
        while self._task_queue and len(self._running_tasks) < self._current_concurrency:
            task = self._task_queue.pop(0)
            
            # Check tool limit again
            tool_limit = self._tool_limits.get(task.tool_name, self._tool_limits["default"])
            running_tool_tasks = sum(
                1 for t in self._running_tasks.values() 
                if t.tool_name == task.tool_name
            )
            
            if running_tool_tasks >= tool_limit:
                # Put it back in queue
                self._task_queue.insert(0, task)
                break
            
            # Execute the task (would need the actual coroutine, which we don't have)
            # For now, just remove from queue and log
            logger.info(f"Dequeued task {task.task_id} (ready to execute)")
    
    def get_status(self) -> Dict:
        """Get current resource manager status."""
        return {
            "current_concurrency": self._current_concurrency,
            "running_tasks": len(self._running_tasks),
            "queued_tasks": len(self._task_queue),
            "resources": self._resource_history[-1].__dict__ if self._resource_history else None,
            "resource_level": self._resource_history[-1].level.value if self._resource_history else None,
        }
    
    def get_resource_history(self, limit: int = 100) -> List[SystemResources]:
        """Get recent resource history."""
        return self._resource_history[-limit:]


@dataclass
class TaskInfo:
    """Information about a running task."""
    task_id: str
    tool_name: str
    start_time: float
    end_time: Optional[float] = None
    success: Optional[bool] = None
    error: Optional[str] = None


# Global resource manager instance
_resource_manager: Optional[ResourceManager] = None


def get_resource_manager() -> ResourceManager:
    """Get or create the global resource manager instance."""
    global _resource_manager
    if _resource_manager is None:
        _resource_manager = ResourceManager()
    return _resource_manager
