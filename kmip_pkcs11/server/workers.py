"""Multi-process worker model.

One PKCS#11 session serialised by a lock is correct but caps throughput at a
single core: every cryptographic operation queues behind the same lock, and a
session pool cannot relieve it, because the binding calls C_Initialize(NULL)
and the library's own thread safety is therefore never enabled (see
pkcs11_shim/shim.py). Separate *processes* sidestep that entirely — each gets
its own PKCS#11 library instance, its own session, and its own lock.

The ordering here is the part that matters. PKCS#11 says a child process must
re-initialize the library after fork, and behaviour when a child inherits an
initialized one is undefined — in practice, crashes. So the parent forks
*before* touching PKCS#11:

    parent: bind the listening socket
    parent: fork N children          <- no PKCS#11 state exists yet
    child:  initialize PKCS#11, then accept() on the inherited socket

Every worker accepts from the one socket and the kernel distributes
connections. Shared state that used to rely on in-process locks had to become
cross-process safe first: the audit hash chain now serialises on a SQLite
write lock, and master-key provisioning on a filesystem lock.
"""

import logging
import os
import signal
import socket
import sys
import time
from typing import Callable, List, Optional

log = logging.getLogger(__name__)


class WorkerPool:
    """Pre-fork worker pool. Binds the socket, forks children, supervises them.

    Children that die are replaced, so a crash in one worker costs the
    connections it was serving rather than the service.
    """

    def __init__(self, host: str, port: int, workers: int,
                 serve: Callable[[socket.socket, int], None],
                 backlog: int = 128):
        self._host = host
        self._port = port
        self._workers = workers
        self._serve = serve
        self._backlog = backlog
        self._sock: Optional[socket.socket] = None
        self._children: List[int] = []
        self._running = False

    # ── lifecycle ───────────────────────────────────────────────────────────

    def bind(self) -> socket.socket:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self._host, self._port))
        sock.listen(self._backlog)
        self._sock = sock
        log.info("Listening on %s:%d, starting %d worker(s)",
                 self._host, self._port, self._workers)
        return sock

    def _spawn(self, index: int) -> int:
        pid = os.fork()
        if pid == 0:
            # ── child ──
            # Reset inherited signal handling: the parent's handlers manage the
            # pool, and a child must not try to supervise its siblings.
            signal.signal(signal.SIGTERM, signal.SIG_DFL)
            signal.signal(signal.SIGINT, signal.SIG_DFL)
            signal.signal(signal.SIGCHLD, signal.SIG_DFL)
            try:
                # PKCS#11 is initialized inside serve(), i.e. after the fork.
                self._serve(self._sock, index)
            except KeyboardInterrupt:
                pass
            except Exception:
                log.exception("Worker %d died", index)
                os._exit(1)
            os._exit(0)
        return pid

    def start(self):
        if self._sock is None:
            self.bind()
        self._running = True
        self._children = [self._spawn(i) for i in range(self._workers)]
        log.info("Workers started: %s", self._children)

    def supervise(self):
        """Block, replacing workers that exit until stop() is called."""
        while self._running:
            try:
                pid, status = os.waitpid(-1, os.WNOHANG)
            except ChildProcessError:
                break
            if pid == 0:
                time.sleep(0.2)
                continue
            if pid in self._children and self._running:
                index = self._children.index(pid)
                log.error("Worker %d (pid %d) exited with status %d — restarting",
                          index, pid, status)
                self._children[index] = self._spawn(index)

    def stop(self, timeout: float = 10.0):
        """Signal workers to finish, then reap them. Escalates to SIGKILL for
        anything still alive at the deadline, so shutdown always terminates."""
        self._running = False
        for pid in self._children:
            try:
                os.kill(pid, signal.SIGTERM)
            except ProcessLookupError:
                pass

        deadline = time.time() + timeout
        remaining = list(self._children)
        while remaining and time.time() < deadline:
            for pid in list(remaining):
                try:
                    reaped, _ = os.waitpid(pid, os.WNOHANG)
                    if reaped:
                        remaining.remove(pid)
                except ChildProcessError:
                    remaining.remove(pid)
            if remaining:
                time.sleep(0.1)

        for pid in remaining:
            log.warning("Worker pid %d did not exit; sending SIGKILL", pid)
            try:
                os.kill(pid, signal.SIGKILL)
                os.waitpid(pid, 0)
            except (ProcessLookupError, ChildProcessError):
                pass

        if self._sock:
            self._sock.close()
            self._sock = None
        self._children = []
        log.info("Worker pool stopped")

    @property
    def children(self) -> List[int]:
        return list(self._children)


def default_worker_count() -> int:
    """One worker per CPU, capped. Past a handful the bottleneck moves to the
    HSM and the SQLite writer anyway, so more processes buy contention rather
    than throughput."""
    return max(1, min(8, (os.cpu_count() or 1)))
