"""Distributed tracing and observability for CTF Toolkit.

Provides OpenTelemetry-compatible tracing, metrics collection, and execution
replay functionality for debugging and performance analysis.
"""

import asyncio
import json
import logging
import tempfile
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Callable
from pathlib import Path

logger = logging.getLogger(__name__)


class SpanStatus(Enum):
    """Span status codes."""
    OK = "ok"
    ERROR = "error"
    UNSET = "unset"


@dataclass
class Span:
    """Represents a single span in a distributed trace."""
    trace_id: str
    span_id: str
    parent_span_id: Optional[str]
    name: str
    kind: str  # internal, server, client, producer, consumer
    start_time: float
    end_time: Optional[float] = None
    status: SpanStatus = SpanStatus.UNSET
    attributes: Dict[str, Any] = field(default_factory=dict)
    events: List[Dict] = field(default_factory=list)
    error: Optional[str] = None
    
    @property
    def duration_ms(self) -> Optional[float]:
        """Get span duration in milliseconds."""
        if self.end_time is None:
            return None
        return (self.end_time - self.start_time) * 1000
    
    def to_dict(self) -> Dict:
        """Convert span to dictionary for serialization."""
        return {
            "trace_id": self.trace_id,
            "span_id": self.span_id,
            "parent_span_id": self.parent_span_id,
            "name": self.name,
            "kind": self.kind,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "duration_ms": self.duration_ms,
            "status": self.status.value,
            "attributes": self.attributes,
            "events": self.events,
            "error": self.error,
        }


class Tracer:
    """
    Distributed tracer for CTF Toolkit.
    
    Provides context propagation, span management, and trace collection
    for debugging and performance analysis.
    """
    
    def __init__(self, service_name: str = "ctfsolver"):
        """
        Initialize tracer.
        
        Args:
            service_name: Name of the service for tracing
        """
        self._service_name = service_name
        self._active_spans: Dict[str, Span] = {}
        self._completed_traces: Dict[str, List[Span]] = {}
        self._exporters: List[Callable] = []
        
        logger.info(f"Tracer initialized: {service_name}")
    
    def start_span(
        self,
        name: str,
        kind: str = "internal",
        parent_context: Optional[Dict] = None,
        attributes: Optional[Dict] = None,
    ) -> Span:
        """
        Start a new span.
        
        Args:
            name: Span name
            kind: Span kind (internal, server, client, etc.)
            parent_context: Optional parent span context
            attributes: Initial attributes
            
        Returns:
            New span
        """
        trace_id = (parent_context.get("trace_id") if parent_context else None) or str(uuid.uuid4())
        parent_span_id = parent_context.get("span_id") if parent_context else None
        span_id = str(uuid.uuid4())
        
        span = Span(
            trace_id=trace_id,
            span_id=span_id,
            parent_span_id=parent_span_id,
            name=name,
            kind=kind,
            start_time=time.time(),
            attributes=attributes or {},
        )
        
        self._active_spans[span_id] = span
        logger.debug(f"Span started: {name} ({span_id})")
        
        return span
    
    def end_span(self, span: Span, status: SpanStatus = SpanStatus.OK, error: Optional[str] = None) -> None:
        """
        End a span.
        
        Args:
            span: Span to end
            status: Span status
            error: Optional error message
        """
        span.end_time = time.time()
        span.status = status
        span.error = error
        
        if span.span_id in self._active_spans:
            del self._active_spans[span.span_id]
        
        # Group by trace_id
        if span.trace_id not in self._completed_traces:
            self._completed_traces[span.trace_id] = []
        self._completed_traces[span.trace_id].append(span)
        
        logger.debug(f"Span ended: {span.name} ({span.span_id}) - {status.value}")
        
        # Export if exporters are configured
        for exporter in self._exporters:
            try:
                exporter(span)
            except Exception as e:
                logger.error(f"Exporter error: {e}")
    
    def add_event(self, span: Span, name: str, attributes: Optional[Dict] = None) -> None:
        """
        Add an event to a span.
        
        Args:
            span: Span to add event to
            name: Event name
            attributes: Event attributes
        """
        event = {
            "name": name,
            "timestamp": time.time(),
            "attributes": attributes or {},
        }
        span.events.append(event)
        logger.debug(f"Event added to {span.name}: {name}")
    
    def set_attribute(self, span: Span, key: str, value: Any) -> None:
        """Set an attribute on a span."""
        span.attributes[key] = value
    
    def get_trace(self, trace_id: str) -> Optional[List[Span]]:
        """Get all spans for a trace."""
        return self._completed_traces.get(trace_id)
    
    def get_recent_traces(self, limit: int = 10) -> List[List[Span]]:
        """Get recent completed traces."""
        traces = list(self._completed_traces.values())
        return traces[-limit:]
    
    def add_exporter(self, exporter: Callable) -> None:
        """Add a span exporter function."""
        self._exporters.append(exporter)
    
    def get_stats(self) -> Dict:
        """Get tracer statistics."""
        active_spans = len(self._active_spans)
        completed_traces = len(self._completed_traces)
        total_spans = sum(len(spans) for spans in self._completed_traces.values())
        
        return {
            "active_spans": active_spans,
            "completed_traces": completed_traces,
            "total_spans": total_spans,
            "service_name": self._service_name,
        }


@dataclass
class MetricPoint:
    """Single metric data point."""
    name: str
    value: float
    timestamp: float = field(default_factory=time.time)
    labels: Dict[str, str] = field(default_factory=dict)
    metric_type: str = "gauge"  # gauge, counter, histogram


class MetricsCollector:
    """
    Metrics collection for CTF Toolkit.
    
    Collects and aggregates performance metrics for monitoring and alerting.
    """
    
    def __init__(self):
        """Initialize metrics collector."""
        self._metrics: List[MetricPoint] = []
        self._counters: Dict[str, float] = {}
        self._gauges: Dict[str, float] = {}
        self._histograms: Dict[str, List[float]] = {}
        
        logger.info("MetricsCollector initialized")
    
    def increment_counter(self, name: str, value: float = 1.0, labels: Optional[Dict] = None) -> None:
        """Increment a counter metric."""
        key = self._make_key(name, labels)
        self._counters[key] = self._counters.get(key, 0) + value
        
        self._metrics.append(MetricPoint(
            name=name,
            value=self._counters[key],
            labels=labels or {},
            metric_type="counter",
        ))
    
    def set_gauge(self, name: str, value: float, labels: Optional[Dict] = None) -> None:
        """Set a gauge metric."""
        key = self._make_key(name, labels)
        self._gauges[key] = value
        
        self._metrics.append(MetricPoint(
            name=name,
            value=value,
            labels=labels or {},
            metric_type="gauge",
        ))
    
    def record_histogram(self, name: str, value: float, labels: Optional[Dict] = None) -> None:
        """Record a histogram value."""
        key = self._make_key(name, labels)
        if key not in self._histograms:
            self._histograms[key] = []
        self._histograms[key].append(value)
        
        self._metrics.append(MetricPoint(
            name=name,
            value=value,
            labels=labels or {},
            metric_type="histogram",
        ))
    
    def _make_key(self, name: str, labels: Optional[Dict]) -> str:
        """Create a unique key from name and labels."""
        if not labels:
            return name
        label_str = ",".join(f"{k}={v}" for k, v in sorted(labels.items()))
        return f"{name}{{{label_str}}}"
    
    def get_counter(self, name: str, labels: Optional[Dict] = None) -> float:
        """Get current counter value."""
        key = self._make_key(name, labels)
        return self._counters.get(key, 0)
    
    def get_gauge(self, name: str, labels: Optional[Dict] = None) -> Optional[float]:
        """Get current gauge value."""
        key = self._make_key(name, labels)
        return self._gauges.get(key)
    
    def get_histogram_stats(self, name: str, labels: Optional[Dict] = None) -> Optional[Dict]:
        """Get histogram statistics."""
        key = self._make_key(name, labels)
        values = self._histograms.get(key, [])
        
        if not values:
            return None
        
        return {
            "count": len(values),
            "sum": sum(values),
            "avg": sum(values) / len(values),
            "min": min(values),
            "max": max(values),
            "p50": sorted(values)[len(values) // 2],
            "p95": sorted(values)[int(len(values) * 0.95)],
            "p99": sorted(values)[int(len(values) * 0.99)] if len(values) >= 100 else max(values),
        }
    
    def get_recent_metrics(self, limit: int = 100) -> List[MetricPoint]:
        """Get recent metric points."""
        return self._metrics[-limit:]
    
    def get_summary(self) -> Dict:
        """Get metrics summary."""
        return {
            "total_metrics": len(self._metrics),
            "counters": len(self._counters),
            "gauges": len(self._gauges),
            "histograms": len(self._histograms),
        }


class ExecutionReplayer:
    """
    Execution replay for debugging.
    
    Records tool executions and allows replaying them for debugging
    and testing purposes.
    """
    
    def __init__(self, replay_dir: Optional[Path] = None):
        """
        Initialize execution replayer.
        
        Args:
            replay_dir: Directory to store replay files
        """
        self._replay_dir = replay_dir or Path(tempfile.gettempdir()) / "ctf-replays"
        self._replay_dir.mkdir(parents=True, exist_ok=True)
        
        self._recordings: Dict[str, Dict] = {}
        self._current_recording: Optional[str] = None
        
        logger.info(f"ExecutionReplayer initialized: {self._replay_dir}")
    
    def start_recording(self, session_id: Optional[str] = None) -> str:
        """Start recording a session."""
        if session_id is None:
            session_id = str(uuid.uuid4())
        
        self._current_recording = session_id
        self._recordings[session_id] = {
            "session_id": session_id,
            "start_time": time.time(),
            "events": [],
            "metadata": {},
        }
        
        logger.info(f"Started recording: {session_id}")
        return session_id
    
    def record_event(self, event_type: str, data: Dict, session_id: Optional[str] = None) -> None:
        """Record an event in the current session."""
        session_id = session_id or self._current_recording
        if not session_id or session_id not in self._recordings:
            logger.warning("No active recording session")
            return
        
        event = {
            "type": event_type,
            "timestamp": time.time(),
            "data": data,
        }
        self._recordings[session_id]["events"].append(event)
    
    def stop_recording(self, session_id: Optional[str] = None) -> Optional[Dict]:
        """Stop recording and return the recording."""
        session_id = session_id or self._current_recording
        if not session_id or session_id not in self._recordings:
            return None
        
        recording = self._recordings[session_id]
        recording["end_time"] = time.time()
        recording["duration"] = recording["end_time"] - recording["start_time"]
        
        # Save to file
        replay_file = self._replay_dir / f"{session_id}.json"
        with open(replay_file, "w") as f:
            json.dump(recording, f, indent=2)
        
        self._current_recording = None
        logger.info(f"Stopped recording: {session_id} ({recording['duration']:.2f}s)")
        
        return recording
    
    def load_recording(self, session_id: str) -> Optional[Dict]:
        """Load a recorded session from file."""
        replay_file = self._replay_dir / f"{session_id}.json"
        if not replay_file.exists():
            return None
        
        with open(replay_file, "r") as f:
            return json.load(f)
    
    async def replay(self, session_id: str, speed: float = 1.0) -> List[Dict]:
        """
        Replay a recorded session.
        
        Args:
            session_id: Session to replay
            speed: Replay speed multiplier
            
        Returns:
            List of replayed events
        """
        recording = self.load_recording(session_id)
        if not recording:
            return []
        
        events = recording["events"]
        replayed = []
        
        for i, event in enumerate(events):
            # Calculate delay from previous event
            if i > 0:
                delay = (event["timestamp"] - events[i-1]["timestamp"]) / speed
                await asyncio.sleep(delay)
            
            # Process event (in real implementation, would execute the tool)
            replayed.append(event)
            logger.debug(f"Replayed event: {event['type']}")
        
        return replayed


# Global instances
_tracer: Optional[Tracer] = None
_metrics: Optional[MetricsCollector] = None
_replayer: Optional[ExecutionReplayer] = None


def get_tracer() -> Tracer:
    """Get or create the global tracer instance."""
    global _tracer
    if _tracer is None:
        _tracer = Tracer()
    return _tracer


def get_metrics() -> MetricsCollector:
    """Get or create the global metrics collector instance."""
    global _metrics
    if _metrics is None:
        _metrics = MetricsCollector()
    return _metrics


def get_replayer() -> ExecutionReplayer:
    """Get or create the global execution replayer instance."""
    global _replayer
    if _replayer is None:
        _replayer = ExecutionReplayer()
    return _replayer
