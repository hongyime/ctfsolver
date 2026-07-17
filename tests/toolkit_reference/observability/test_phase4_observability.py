"""Observability and debugging tests for CTF Toolkit Phase 4.

Tests distributed tracing, metrics collection, profiling, and health checking.
"""

import asyncio
import sys
import time
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from src.ctf_core.observability.tracing import (
    Tracer, MetricsCollector, ExecutionReplayer,
    SpanStatus, get_tracer, get_metrics, get_replayer
)
from src.ctf_core.debug.debugger import (
    PerformanceProfiler, HealthChecker, InteractiveDebugger,
    get_profiler, get_health_checker, get_debugger
)


class TestTracer(unittest.TestCase):
    """Test distributed tracing functionality."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.tracer = Tracer(service_name="test-service")
    
    def test_span_creation(self):
        """Test span creation."""
        span = self.tracer.start_span("test_operation")
        
        self.assertIsNotNone(span.trace_id)
        self.assertIsNotNone(span.span_id)
        self.assertIsNone(span.parent_span_id)
        self.assertEqual(span.name, "test_operation")
        self.assertIsNotNone(span.start_time)
        self.assertIsNone(span.end_time)
    
    def test_span_with_parent(self):
        """Test span creation with parent context."""
        parent_span = self.tracer.start_span("parent_operation")
        parent_context = {
            "trace_id": parent_span.trace_id,
            "span_id": parent_span.span_id,
        }
        
        child_span = self.tracer.start_span("child_operation", parent_context=parent_context)
        
        self.assertEqual(child_span.trace_id, parent_span.trace_id)
        self.assertEqual(child_span.parent_span_id, parent_span.span_id)
    
    def test_span_lifecycle(self):
        """Test span start and end."""
        span = self.tracer.start_span("test_operation")
        self.assertIn(span.span_id, self.tracer._active_spans)
        
        self.tracer.end_span(span, status=SpanStatus.OK)
        self.assertNotIn(span.span_id, self.tracer._active_spans)
        self.assertIsNotNone(span.end_time)
        self.assertEqual(span.status, SpanStatus.OK)
    
    def test_span_duration(self):
        """Test span duration calculation."""
        span = self.tracer.start_span("test_operation")
        time.sleep(0.1)
        self.tracer.end_span(span)
        
        self.assertIsNotNone(span.duration_ms)
        self.assertGreaterEqual(span.duration_ms, 100)  # At least 100ms
    
    def test_add_event(self):
        """Test adding events to span."""
        span = self.tracer.start_span("test_operation")
        self.tracer.add_event(span, "event1", {"key": "value"})
        
        self.assertEqual(len(span.events), 1)
        self.assertEqual(span.events[0]["name"], "event1")
        self.assertEqual(span.events[0]["attributes"]["key"], "value")
    
    def test_set_attribute(self):
        """Test setting span attributes."""
        span = self.tracer.start_span("test_operation")
        self.tracer.set_attribute(span, "http.method", "GET")
        
        self.assertEqual(span.attributes["http.method"], "GET")
    
    def test_get_trace(self):
        """Test retrieving a complete trace."""
        parent_span = self.tracer.start_span("parent")
        parent_context = {"trace_id": parent_span.trace_id, "span_id": parent_span.span_id}
        
        child_span = self.tracer.start_span("child", parent_context=parent_context)
        
        self.tracer.end_span(parent_span)
        self.tracer.end_span(child_span)
        
        trace = self.tracer.get_trace(parent_span.trace_id)
        self.assertIsNotNone(trace)
        self.assertEqual(len(trace), 2)
    
    def test_tracer_stats(self):
        """Test tracer statistics."""
        span1 = self.tracer.start_span("op1")
        span2 = self.tracer.start_span("op2")
        
        stats = self.tracer.get_stats()
        self.assertEqual(stats["active_spans"], 2)
        
        self.tracer.end_span(span1)
        stats = self.tracer.get_stats()
        self.assertEqual(stats["active_spans"], 1)
        self.assertEqual(stats["total_spans"], 1)


class TestMetricsCollector(unittest.TestCase):
    """Test metrics collection functionality."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.collector = MetricsCollector()
    
    def test_counter_increment(self):
        """Test counter increment."""
        self.collector.increment_counter("requests", 1)
        self.assertEqual(self.collector.get_counter("requests"), 1)
        
        self.collector.increment_counter("requests", 5)
        self.assertEqual(self.collector.get_counter("requests"), 6)
    
    def test_counter_with_labels(self):
        """Test counter with labels."""
        self.collector.increment_counter("requests", 1, {"method": "GET"})
        self.collector.increment_counter("requests", 1, {"method": "POST"})
        
        self.assertEqual(self.collector.get_counter("requests", {"method": "GET"}), 1)
        self.assertEqual(self.collector.get_counter("requests", {"method": "POST"}), 1)
    
    def test_gauge_set(self):
        """Test gauge setting."""
        self.collector.set_gauge("temperature", 25.5)
        self.assertEqual(self.collector.get_gauge("temperature"), 25.5)
        
        self.collector.set_gauge("temperature", 30.0)
        self.assertEqual(self.collector.get_gauge("temperature"), 30.0)
    
    def test_histogram_recording(self):
        """Test histogram recording."""
        for i in range(100):
            self.collector.record_histogram("latency", i * 10)
        
        stats = self.collector.get_histogram_stats("latency")
        self.assertIsNotNone(stats)
        self.assertEqual(stats["count"], 100)
        self.assertEqual(stats["min"], 0)
        self.assertEqual(stats["max"], 990)
        self.assertEqual(stats["avg"], 495)
    
    def test_metrics_summary(self):
        """Test metrics summary."""
        self.collector.increment_counter("counter1", 1)
        self.collector.set_gauge("gauge1", 10)
        self.collector.record_histogram("histogram1", 5)
        
        summary = self.collector.get_summary()
        self.assertGreaterEqual(summary["total_metrics"], 3)
        self.assertGreaterEqual(summary["counters"], 1)
        self.assertGreaterEqual(summary["gauges"], 1)
        self.assertGreaterEqual(summary["histograms"], 1)


class TestExecutionReplayer(unittest.TestCase):
    """Test execution replay functionality."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.replayer = ExecutionReplayer()
    
    def test_recording_session(self):
        """Test recording a session."""
        session_id = self.replayer.start_recording()
        self.assertIsNotNone(session_id)
        self.assertEqual(self.replayer._current_recording, session_id)
        
        self.replayer.record_event("tool_execution", {"tool": "nmap", "target": "192.168.1.1"})
        
        recording = self.replayer.stop_recording()
        self.assertIsNotNone(recording)
        self.assertEqual(len(recording["events"]), 1)
        self.assertEqual(recording["events"][0]["data"]["tool"], "nmap")
    
    def test_custom_session_id(self):
        """Test custom session ID."""
        session_id = self.replayer.start_recording("my-session")
        self.assertEqual(session_id, "my-session")
    
    def test_load_recording(self):
        """Test loading a recorded session."""
        session_id = self.replayer.start_recording()
        self.replayer.record_event("test_event", {"key": "value"})
        self.replayer.stop_recording()
        
        loaded = self.replayer.load_recording(session_id)
        self.assertIsNotNone(loaded)
        self.assertEqual(len(loaded["events"]), 1)


class TestPerformanceProfiler(unittest.TestCase):
    """Test performance profiling functionality."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.profiler = PerformanceProfiler()
    
    def test_profiling_session(self):
        """Test profiling a session."""
        self.profiler.start_profiling("test_session")
        
        # Do some work
        total = 0
        for i in range(1000):
            total += i
        
        results = self.profiler.stop_profiling("test_session")
        
        self.assertGreater(len(results), 0)
        # Results should contain profiled functions
        self.assertIsInstance(results, list)
        self.assertIsInstance(results[0].function_name, str)
        self.assertGreater(results[0].total_calls, 0)
    
    def test_profile_function(self):
        """Test profiling a single function."""
        def test_function():
            total = 0
            for i in range(10000):
                total += i
            return total
        
        result, results = self.profiler.profile_function(test_function)
        
        self.assertEqual(result, sum(range(10000)))
        self.assertGreater(len(results), 0)
    
    def test_get_top_functions(self):
        """Test getting top functions."""
        self.profiler.start_profiling("test_session")
        
        def slow_function():
            time.sleep(0.1)
        
        slow_function()
        
        results = self.profiler.stop_profiling("test_session")
        top = self.profiler.get_top_functions("test_session", limit=5)
        
        self.assertLessEqual(len(top), 5)
    
    def test_export_results(self):
        """Test exporting profiling results."""
        import tempfile
        
        self.profiler.start_profiling("test_session")
        sum(range(1000))
        results = self.profiler.stop_profiling("test_session")
        
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            output_path = Path(f.name)
        
        try:
            self.profiler.export_results("test_session", output_path)
            self.assertTrue(output_path.exists())
        finally:
            output_path.unlink()


class TestHealthChecker(unittest.TestCase):
    """Test health checking functionality."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.checker = HealthChecker()
    
    def test_health_check_registration(self):
        """Test health check registration."""
        def custom_check():
            return "healthy", "Custom check passed", {}
        
        self.checker.register_check("custom", custom_check)
        self.assertIn("custom", self.checker._checks)
    
    def test_run_checks(self):
        """Test running health checks."""
        results = asyncio.run(self.checker.run_checks())
        
        self.assertIsInstance(results, dict)
        self.assertGreater(len(results), 0)
        
        for name, result in results.items():
            self.assertIn(result.status, ["healthy", "degraded", "unhealthy"])
    
    def test_get_status(self):
        """Test overall status calculation."""
        # Before any checks
        self.assertEqual(self.checker.get_status(), "unknown")
        
        # After checks
        asyncio.run(self.checker.run_checks())
        status = self.checker.get_status()
        self.assertIn(status, ["healthy", "degraded", "unhealthy", "unknown"])
    
    def test_get_summary(self):
        """Test health summary."""
        asyncio.run(self.checker.run_checks())
        summary = self.checker.get_summary()
        
        self.assertIn("status", summary)
        self.assertIn("components", summary)
        self.assertIsInstance(summary["components"], dict)


class TestInteractiveDebugger(unittest.TestCase):
    """Test interactive debugging functionality."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.debugger = InteractiveDebugger()
    
    def test_breakpoint_management(self):
        """Test breakpoint setting and clearing."""
        self.debugger.set_breakpoint("test_function", 42)
        self.assertTrue(self.debugger.check_breakpoint("test_function", 42))
        self.assertFalse(self.debugger.check_breakpoint("test_function", 43))
        
        self.debugger.clear_breakpoints()
        self.assertFalse(self.debugger.check_breakpoint("test_function", 42))
    
    def test_pause_resume(self):
        """Test pause and resume."""
        self.assertFalse(self.debugger.is_paused)
        
        self.debugger.pause({"x": 1, "y": 2})
        self.assertTrue(self.debugger.is_paused)
        self.assertEqual(self.debugger.get_variables(), {"x": 1, "y": 2})
        
        self.debugger.resume()
        self.assertFalse(self.debugger.is_paused)


class TestSingletons(unittest.TestCase):
    """Test singleton patterns."""
    
    def test_tracer_singleton(self):
        """Test tracer singleton."""
        tracer1 = get_tracer()
        tracer2 = get_tracer()
        self.assertIs(tracer1, tracer2)
    
    def test_metrics_singleton(self):
        """Test metrics singleton."""
        metrics1 = get_metrics()
        metrics2 = get_metrics()
        self.assertIs(metrics1, metrics2)
    
    def test_replayer_singleton(self):
        """Test replayer singleton."""
        replayer1 = get_replayer()
        replayer2 = get_replayer()
        self.assertIs(replayer1, replayer2)
    
    def test_profiler_singleton(self):
        """Test profiler singleton."""
        profiler1 = get_profiler()
        profiler2 = get_profiler()
        self.assertIs(profiler1, profiler2)
    
    def test_health_checker_singleton(self):
        """Test health checker singleton."""
        checker1 = get_health_checker()
        checker2 = get_health_checker()
        self.assertIs(checker1, checker2)
    
    def test_debugger_singleton(self):
        """Test debugger singleton."""
        debugger1 = get_debugger()
        debugger2 = get_debugger()
        self.assertIs(debugger1, debugger2)


def run_observability_tests():
    """Run all observability tests and generate report."""
    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Add test classes
    suite.addTests(loader.loadTestsFromTestCase(TestTracer))
    suite.addTests(loader.loadTestsFromTestCase(TestMetricsCollector))
    suite.addTests(loader.loadTestsFromTestCase(TestExecutionReplayer))
    suite.addTests(loader.loadTestsFromTestCase(TestPerformanceProfiler))
    suite.addTests(loader.loadTestsFromTestCase(TestHealthChecker))
    suite.addTests(loader.loadTestsFromTestCase(TestInteractiveDebugger))
    suite.addTests(loader.loadTestsFromTestCase(TestSingletons))
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Generate report
    report = {
        "total_tests": result.testsRun,
        "failures": len(result.failures),
        "errors": len(result.errors),
        "success": result.wasSuccessful(),
    }
    
    print("\n" + "="*70)
    print("OBSERVABILITY TEST REPORT (Phase 4)")
    print("="*70)
    print(f"Total Tests: {report['total_tests']}")
    print(f"Failures: {report['failures']}")
    print(f"Errors: {report['errors']}")
    print(f"Status: {'✅ PASSED' if report['success'] else '❌ FAILED'}")
    print("="*70)
    
    return report


if __name__ == "__main__":
    report = run_observability_tests()
    sys.exit(0 if report["success"] else 1)
