"""Debugging tools for CTF Toolkit.

Provides interactive debugging, performance profiling, and health check
capabilities for troubleshooting and optimization.
"""

import asyncio
import cProfile
import io
import json
import logging
import pstats
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


@dataclass
class ProfileResult:
    """Results from a profiling session."""
    function_name: str
    total_calls: int
    total_time: float
    cumulative_time: float
    primitive_time: float
    file_location: str
    
    @property
    def time_per_call(self) -> float:
        """Calculate average time per call."""
        if self.total_calls == 0:
            return 0
        return self.total_time / self.total_calls


class PerformanceProfiler:
    """
    Performance profiler for CTF Toolkit.
    
    Provides function-level profiling to identify performance bottlenecks.
    """
    
    def __init__(self):
        """Initialize profiler."""
        self._profiles: Dict[str, cProfile.Profile] = {}
        self._results: Dict[str, List[ProfileResult]] = {}
        
        logger.info("PerformanceProfiler initialized")
    
    def start_profiling(self, session_id: str = "default") -> None:
        """Start profiling a session."""
        if session_id in self._profiles:
            logger.warning(f"Profile session {session_id} already exists")
            return
        
        profiler = cProfile.Profile()
        profiler.enable()
        self._profiles[session_id] = profiler
        
        logger.info(f"Started profiling: {session_id}")
    
    def stop_profiling(self, session_id: str = "default") -> List[ProfileResult]:
        """Stop profiling and return results."""
        if session_id not in self._profiles:
            return []
        
        profiler = self._profiles[session_id]
        profiler.disable()
        
        # Process results
        stream = io.StringIO()
        stats = pstats.Stats(profiler, stream=stream)
        stats.sort_stats("cumulative")
        
        results = []
        for func_key, func_stats in getattr(stats, "stats", {}).items():
            filename, line_number, func_name = func_key
            calls, primitive_calls, total_time, cumulative_time, _ = func_stats
            
            results.append(ProfileResult(
                function_name=func_name,
                total_calls=calls,
                total_time=total_time,
                cumulative_time=cumulative_time,
                primitive_time=primitive_calls,
                file_location=f"{filename}:{line_number}",
            ))
        
        # Sort by cumulative time
        results.sort(key=lambda r: r.cumulative_time, reverse=True)
        
        self._results[session_id] = results
        del self._profiles[session_id]
        
        logger.info(f"Stopped profiling: {session_id} ({len(results)} functions)")
        return results
    
    def profile_function(self, func: Callable, *args, **kwargs) -> Tuple[Any, List[ProfileResult]]:
        """
        Profile a single function call.
        
        Args:
            func: Function to profile
            *args: Function arguments
            **kwargs: Function keyword arguments
            
        Returns:
            Tuple of (function result, profile results)
        """
        profiler = cProfile.Profile()
        profiler.enable()
        
        try:
            result = func(*args, **kwargs)
        finally:
            profiler.disable()
        
        # Process results
        stream = io.StringIO()
        stats = pstats.Stats(profiler, stream=stream)
        stats.sort_stats("cumulative")
        
        results = []
        for func_key, func_stats in getattr(stats, "stats", {}).items():
            filename, line_number, func_name = func_key
            calls, primitive_calls, total_time, cumulative_time, _ = func_stats
            
            results.append(ProfileResult(
                function_name=func_name,
                total_calls=calls,
                total_time=total_time,
                cumulative_time=cumulative_time,
                primitive_time=primitive_calls,
                file_location=f"{filename}:{line_number}",
            ))
        
        results.sort(key=lambda r: r.cumulative_time, reverse=True)
        
        return result, results
    
    async def profile_async_function(
        self,
        func: Callable,
        *args,
        **kwargs
    ) -> Tuple[Any, List[ProfileResult]]:
        """
        Profile an async function.
        
        Args:
            func: Async function to profile
            *args: Function arguments
            **kwargs: Function keyword arguments
            
        Returns:
            Tuple of (function result, profile results)
        """
        start_time = time.time()
        result = await func(*args, **kwargs)
        end_time = time.time()
        
        # Create synthetic profile result for async functions
        _code = getattr(func, "__code__", None)
        results = [ProfileResult(
            function_name=getattr(func, "__name__", "<anonymous>"),
            total_calls=1,
            total_time=end_time - start_time,
            cumulative_time=end_time - start_time,
            primitive_time=end_time - start_time,
            file_location=f"{func.__module__}:{_code.co_firstlineno if _code else 0}",
        )]
        
        return result, results
    
    def get_results(self, session_id: str) -> Optional[List[ProfileResult]]:
        """Get profiling results for a session."""
        return self._results.get(session_id)
    
    def get_top_functions(self, session_id: str, limit: int = 10) -> List[ProfileResult]:
        """Get top functions by cumulative time."""
        results = self._results.get(session_id, [])
        return results[:limit]
    
    def export_results(self, session_id: str, output_path: Path) -> None:
        """Export profiling results to a file."""
        results = self._results.get(session_id, [])
        
        output_data = {
            "session_id": session_id,
            "results": [r.__dict__ for r in results],
            "summary": {
                "total_functions": len(results),
                "total_time": sum(r.total_time for r in results),
                "top_function": results[0].function_name if results else None,
            }
        }
        
        with open(output_path, "w") as f:
            json.dump(output_data, f, indent=2)
        
        logger.info(f"Exported profiling results to {output_path}")


@dataclass
class HealthCheckResult:
    """Result of a health check."""
    component: str
    status: str  # healthy, degraded, unhealthy
    message: str
    latency_ms: Optional[float] = None
    details: Dict = field(default_factory=dict)


class HealthChecker:
    """
    Health checking for CTF Toolkit components.
    
    Monitors the health of various system components and provides
    a dashboard for operational visibility.
    """
    
    def __init__(self):
        """Initialize health checker."""
        self._checks: Dict[str, Callable] = {}
        self._last_results: Dict[str, HealthCheckResult] = {}
        
        # Register default checks
        self._register_default_checks()
        
        logger.info("HealthChecker initialized")
    
    def _register_default_checks(self) -> None:
        """Register default health checks."""
        self.register_check("database", self._check_database)
        self.register_check("docker", self._check_docker)
        self.register_check("memory", self._check_memory)
        self.register_check("disk", self._check_disk)
        self.register_check("network", self._check_network)
    
    def register_check(self, name: str, check_func: Callable) -> None:
        """Register a health check function."""
        self._checks[name] = check_func
        logger.debug(f"Registered health check: {name}")
    
    async def run_checks(self) -> Dict[str, HealthCheckResult]:
        """Run all registered health checks."""
        results = {}
        
        for name, check_func in self._checks.items():
            try:
                start_time = time.time()
                if asyncio.iscoroutinefunction(check_func):
                    status, message, details = await check_func()
                else:
                    status, message, details = check_func()
                latency = (time.time() - start_time) * 1000
                
                result = HealthCheckResult(
                    component=name,
                    status=status,
                    message=message,
                    latency_ms=latency,
                    details=details,
                )
            except Exception as e:
                result = HealthCheckResult(
                    component=name,
                    status="unhealthy",
                    message=f"Check failed: {str(e)}",
                    latency_ms=None,
                )
            
            results[name] = result
            self._last_results[name] = result
        
        return results
    
    async def _check_database(self) -> Tuple[str, str, Dict]:
        """Check database health."""
        try:
            from src.ctf_core.db import get_database
            
            start_time = time.time()
            db = await get_database()
            
            # Simple query to test connectivity
            if db._db is None:
                return "unhealthy", "Database not connected", {}
            cursor = await db._db.execute("SELECT 1")
            await cursor.fetchone()
            latency = (time.time() - start_time) * 1000
            
            return "healthy", f"Database responsive ({latency:.1f}ms)", {"latency_ms": latency}
        except Exception as e:
            return "unhealthy", f"Database error: {str(e)}", {}
    
    async def _check_docker(self) -> Tuple[str, str, Dict]:
        """Check Docker availability."""
        try:
            import docker
            
            client = docker.from_env()
            client.ping()
            
            return "healthy", "Docker daemon available", {}
        except Exception as e:
            return "degraded", f"Docker unavailable: {str(e)}", {}
    
    async def _check_memory(self) -> Tuple[str, str, Dict]:
        """Check memory usage."""
        try:
            import psutil
            
            memory = psutil.virtual_memory()
            percent = memory.percent
            
            if percent < 70:
                return "healthy", f"Memory usage: {percent}%", {"percent": percent}
            elif percent < 90:
                return "degraded", f"High memory usage: {percent}%", {"percent": percent}
            else:
                return "unhealthy", f"Critical memory usage: {percent}%", {"percent": percent}
        except Exception as e:
            return "unhealthy", f"Memory check failed: {str(e)}", {}
    
    async def _check_disk(self) -> Tuple[str, str, Dict]:
        """Check disk usage."""
        try:
            import psutil
            
            disk = psutil.disk_usage("/")
            percent = disk.percent
            
            if percent < 80:
                return "healthy", f"Disk usage: {percent}%", {"percent": percent}
            elif percent < 95:
                return "degraded", f"High disk usage: {percent}%", {"percent": percent}
            else:
                return "unhealthy", f"Critical disk usage: {percent}%", {"percent": percent}
        except Exception as e:
            return "unhealthy", f"Disk check failed: {str(e)}", {}
    
    async def _check_network(self) -> Tuple[str, str, Dict]:
        """Check network connectivity."""
        try:
            import socket
            
            # Test DNS resolution
            socket.getaddrinfo("google.com", 80)
            
            return "healthy", "Network connectivity OK", {}
        except Exception as e:
            return "degraded", f"Network issue: {str(e)}", {}
    
    def get_status(self) -> str:
        """Get overall system status."""
        if not self._last_results:
            return "unknown"
        
        statuses = [r.status for r in self._last_results.values()]
        
        if all(s == "healthy" for s in statuses):
            return "healthy"
        elif any(s == "unhealthy" for s in statuses):
            return "unhealthy"
        else:
            return "degraded"
    
    def get_summary(self) -> Dict:
        """Get health check summary."""
        return {
            "status": self.get_status(),
            "components": {
                name: {
                    "status": result.status,
                    "message": result.message,
                    "latency_ms": result.latency_ms,
                    "details": result.details,
                }
                for name, result in self._last_results.items()
            },
        }


class InteractiveDebugger:
    """
    Interactive debugger for CTF Toolkit.
    
    Provides breakpoints, step-through execution, and variable inspection
    for debugging tool executions.
    """
    
    def __init__(self):
        """Initialize debugger."""
        self._breakpoints: List[Tuple[str, int]] = []
        self._is_paused = False
        self._current_context: Optional[Dict] = None
        
        logger.info("InteractiveDebugger initialized")
    
    def set_breakpoint(self, function_name: str, line_number: int) -> None:
        """Set a breakpoint."""
        self._breakpoints.append((function_name, line_number))
        logger.info(f"Breakpoint set: {function_name}:{line_number}")
    
    def clear_breakpoints(self) -> None:
        """Clear all breakpoints."""
        self._breakpoints.clear()
        logger.info("All breakpoints cleared")
    
    def check_breakpoint(self, function_name: str, line_number: int) -> bool:
        """Check if there's a breakpoint at the given location."""
        return (function_name, line_number) in self._breakpoints
    
    def pause(self, context: Optional[Dict] = None) -> None:
        """Pause execution."""
        self._is_paused = True
        self._current_context = context
        logger.info("Execution paused")
    
    def resume(self) -> None:
        """Resume execution."""
        self._is_paused = False
        logger.info("Execution resumed")
    
    def step_over(self) -> None:
        """Step over to next line."""
        logger.info("Stepping over")
    
    def step_into(self) -> None:
        """Step into function."""
        logger.info("Stepping into")
    
    def get_variables(self) -> Dict:
        """Get current variable context."""
        return self._current_context or {}
    
    @property
    def is_paused(self) -> bool:
        """Check if execution is paused."""
        return self._is_paused


# Global instances
_profiler: Optional[PerformanceProfiler] = None
_health_checker: Optional[HealthChecker] = None
_debugger: Optional[InteractiveDebugger] = None


def get_profiler() -> PerformanceProfiler:
    """Get or create the global profiler instance."""
    global _profiler
    if _profiler is None:
        _profiler = PerformanceProfiler()
    return _profiler


def get_health_checker() -> HealthChecker:
    """Get or create the global health checker instance."""
    global _health_checker
    if _health_checker is None:
        _health_checker = HealthChecker()
    return _health_checker


def get_debugger() -> InteractiveDebugger:
    """Get or create the global debugger instance."""
    global _debugger
    if _debugger is None:
        _debugger = InteractiveDebugger()
    return _debugger
