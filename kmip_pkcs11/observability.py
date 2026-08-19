"""Health checks, metrics and structured logging.

A KMS that cannot be monitored cannot be operated: without these, the only
signal that the HSM session has died is clients failing. Everything here is
stdlib — no Prometheus client library — because the exposition format is a
few lines of text and the dependency is not worth it.
"""

import json
import logging
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Dict, Optional

log = logging.getLogger(__name__)


# ── metrics ──────────────────────────────────────────────────────────────────

class Metrics:
    """Counters and latency totals, keyed by operation and result.

    Deliberately not a histogram: buckets need tuning per deployment, and a
    running total plus a count already answers "is latency drifting?" — which
    is the question that matters before there is production traffic to tune
    against."""

    def __init__(self):
        self._lock = threading.Lock()
        self._operations: Dict[tuple, int] = {}
        self._latency_sum: Dict[str, float] = {}
        self._latency_count: Dict[str, int] = {}
        self._auth_failures = 0
        self._started = time.time()

    def record_operation(self, operation: str, result: str, duration_seconds: float):
        with self._lock:
            key = (operation, result)
            self._operations[key] = self._operations.get(key, 0) + 1
            self._latency_sum[operation] = self._latency_sum.get(operation, 0.0) + duration_seconds
            self._latency_count[operation] = self._latency_count.get(operation, 0) + 1

    def record_auth_failure(self):
        with self._lock:
            self._auth_failures += 1

    def snapshot(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "uptime_seconds": time.time() - self._started,
                "operations": {f"{op}/{res}": n for (op, res), n in self._operations.items()},
                "auth_failures": self._auth_failures,
                "latency_seconds": {
                    op: {"sum": self._latency_sum[op], "count": self._latency_count[op]}
                    for op in self._latency_sum
                },
            }

    def render_prometheus(self) -> str:
        with self._lock:
            lines = [
                "# HELP kmip_uptime_seconds Time since the server started.",
                "# TYPE kmip_uptime_seconds gauge",
                f"kmip_uptime_seconds {time.time() - self._started:.3f}",
                "# HELP kmip_operations_total KMIP operations processed.",
                "# TYPE kmip_operations_total counter",
            ]
            for (op, result), count in sorted(self._operations.items()):
                lines.append(f'kmip_operations_total{{operation="{op}",result="{result}"}} {count}')

            lines += [
                "# HELP kmip_operation_duration_seconds Cumulative operation handling time.",
                "# TYPE kmip_operation_duration_seconds summary",
            ]
            for op in sorted(self._latency_sum):
                lines.append(
                    f'kmip_operation_duration_seconds_sum{{operation="{op}"}} '
                    f'{self._latency_sum[op]:.6f}'
                )
                lines.append(
                    f'kmip_operation_duration_seconds_count{{operation="{op}"}} '
                    f'{self._latency_count[op]}'
                )

            lines += [
                "# HELP kmip_auth_failures_total Rejected authentication attempts.",
                "# TYPE kmip_auth_failures_total counter",
                f"kmip_auth_failures_total {self._auth_failures}",
            ]
            return "\n".join(lines) + "\n"


# ── structured logging ───────────────────────────────────────────────────────

class JSONFormatter(logging.Formatter):
    """One JSON object per line, so a log shipper can parse records without
    regexes. Exception text goes in a field rather than trailing newlines,
    which is what makes multi-line tracebacks survive log aggregation intact."""

    def format(self, record: logging.LogRecord) -> str:
        entry = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(record.created))
                         + f".{int(record.msecs):03d}Z",
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            entry["exception"] = self.formatException(record.exc_info)
        for key, value in record.__dict__.items():
            if key.startswith("kmip_"):
                entry[key[5:]] = value
        return json.dumps(entry, default=str)


def configure_logging(level: str = "INFO", fmt: str = "json"):
    handler = logging.StreamHandler()
    if fmt == "json":
        handler.setFormatter(JSONFormatter())
    else:
        handler.setFormatter(logging.Formatter(
            "%(asctime)s %(levelname)-7s %(name)s: %(message)s"))

    root = logging.getLogger()
    # Replace rather than add, so re-configuring (tests, reloads) doesn't
    # duplicate every line.
    for existing in list(root.handlers):
        root.removeHandler(existing)
    root.addHandler(handler)
    root.setLevel(getattr(logging, level.upper(), logging.INFO))


# ── health endpoint ──────────────────────────────────────────────────────────

class HealthServer:
    """Small HTTP listener exposing /health, /ready and /metrics.

    Separate from the KMIP port on purpose: health and metrics are for the
    operator and the orchestrator, and should not be reachable by KMIP clients
    or require a KMIP credential to read. Bind it to localhost or a management
    interface."""

    def __init__(self, metrics: Metrics, readiness_check=None,
                 host: str = "127.0.0.1", port: int = 9696):
        self._metrics = metrics
        self._readiness_check = readiness_check
        self._host = host
        self._port = port
        self._httpd: Optional[HTTPServer] = None
        self._thread: Optional[threading.Thread] = None

    def start(self):
        metrics, readiness = self._metrics, self._readiness_check

        class Handler(BaseHTTPRequestHandler):
            def _respond(self, code: int, body: str, content_type: str):
                payload = body.encode("utf-8")
                self.send_response(code)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def do_GET(self):  # noqa: N802 - required by BaseHTTPRequestHandler
                if self.path == "/health":
                    # Liveness: the process is up and serving. Deliberately
                    # does not touch the HSM — a liveness probe that fails on a
                    # transient HSM blip would restart a server that is fine.
                    self._respond(200, json.dumps({"status": "ok"}), "application/json")
                elif self.path == "/ready":
                    ok, detail = (True, {})
                    if readiness is not None:
                        try:
                            ok, detail = readiness()
                        except Exception as e:
                            ok, detail = False, {"error": str(e)}
                    body = json.dumps({"status": "ready" if ok else "not-ready", **detail})
                    self._respond(200 if ok else 503, body, "application/json")
                elif self.path == "/metrics":
                    self._respond(200, metrics.render_prometheus(), "text/plain; version=0.0.4")
                else:
                    self._respond(404, json.dumps({"error": "not found"}), "application/json")

            def log_message(self, *args):
                pass  # health probes would otherwise flood the log

        self._httpd = HTTPServer((self._host, self._port), Handler)
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()
        log.info("Health endpoint listening on %s:%d", self._host, self._port)

    def stop(self):
        if self._httpd:
            self._httpd.shutdown()
            self._httpd.server_close()
            self._httpd = None

    @property
    def port(self) -> int:
        return self._httpd.server_address[1] if self._httpd else self._port
