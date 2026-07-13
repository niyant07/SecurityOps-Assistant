"""Multi-threaded task execution built on Qt's ``QThreadPool``.

Two complementary primitives are provided:

* :class:`Worker` — runs an arbitrary callable off the GUI thread and emits
  ``result`` / ``error`` / ``finished`` signals back on the main thread.
* :class:`CommandRunner` — streams stdout/stderr from an external process
  (e.g. a launched Kali tool) line by line, with cancellation support.

Both integrate with :class:`TaskManager`, a thin wrapper over the global thread
pool that keeps references to active runners so they are not garbage collected
mid-flight.
"""

from __future__ import annotations

import subprocess
import traceback
from typing import Any, Callable, Sequence

from PySide6.QtCore import QObject, QProcess, QRunnable, QThreadPool, Signal, Slot

from .logging_config import get_logger

_LOG = get_logger("tasks")


# --------------------------------------------------------------------------- #
# Generic callable worker
# --------------------------------------------------------------------------- #
class WorkerSignals(QObject):
    """Signals emitted by a :class:`Worker` (owned separately: QRunnable is not a QObject)."""

    started = Signal()
    finished = Signal()
    result = Signal(object)
    error = Signal(str)
    progress = Signal(int)


class Worker(QRunnable):
    """Run ``fn(*args, **kwargs)`` on a pool thread.

    If *fn* accepts a ``progress_callback`` keyword it will receive a callable
    that emits the ``progress`` signal (0-100).
    """

    def __init__(self, fn: Callable[..., Any], *args: Any, **kwargs: Any) -> None:
        super().__init__()
        self._fn = fn
        self._args = args
        self._kwargs = kwargs
        self.signals = WorkerSignals()

    @Slot()
    def run(self) -> None:  # noqa: D401 - Qt entry point
        self.signals.started.emit()
        try:
            code = getattr(self._fn, "__code__", None)
            if code is not None and "progress_callback" in code.co_varnames:
                self._kwargs.setdefault("progress_callback", self.signals.progress.emit)
            outcome = self._fn(*self._args, **self._kwargs)
        except Exception as exc:  # noqa: BLE001 - report all failures to the UI
            _LOG.exception("Worker failed: %s", exc)
            self.signals.error.emit(f"{exc}\n{traceback.format_exc()}")
        else:
            self.signals.result.emit(outcome)
        finally:
            self.signals.finished.emit()


# --------------------------------------------------------------------------- #
# External command runner
# --------------------------------------------------------------------------- #
class CommandRunner(QObject):
    """Run an external command via :class:`QProcess`, streaming output.

    Signals
    -------
    output(str): a chunk of combined stdout/stderr text
    finished(int): the process exit code
    failed(str): the process could not be started
    """

    output = Signal(str)
    finished = Signal(int)
    failed = Signal(str)

    def __init__(self, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._proc: QProcess | None = None

    def start(self, program: str, arguments: Sequence[str]) -> None:
        """Start *program* with *arguments* (already split, not shell-quoted)."""
        proc = QProcess(self)
        proc.setProcessChannelMode(QProcess.ProcessChannelMode.MergedChannels)
        proc.readyReadStandardOutput.connect(self._on_ready)
        proc.finished.connect(self._on_finished)
        proc.errorOccurred.connect(self._on_error)
        self._proc = proc
        _LOG.info("Launching: %s %s", program, " ".join(arguments))
        proc.start(program, list(arguments))

    @Slot()
    def _on_ready(self) -> None:
        if not self._proc:
            return
        data = bytes(self._proc.readAllStandardOutput()).decode("utf-8", errors="replace")
        if data:
            self.output.emit(data)

    @Slot(int, QProcess.ExitStatus)
    def _on_finished(self, code: int, _status: QProcess.ExitStatus) -> None:
        _LOG.info("Process finished with exit code %s", code)
        self.finished.emit(int(code))

    @Slot(QProcess.ProcessError)
    def _on_error(self, err: QProcess.ProcessError) -> None:
        message = self._proc.errorString() if self._proc else str(err)
        _LOG.error("Process error: %s", message)
        self.failed.emit(message)

    def cancel(self) -> None:
        """Terminate the running process (SIGTERM, then kill if needed)."""
        if self._proc and self._proc.state() != QProcess.ProcessState.NotRunning:
            _LOG.info("Cancelling running process")
            self._proc.terminate()
            if not self._proc.waitForFinished(2000):
                self._proc.kill()

    def is_running(self) -> bool:
        return bool(self._proc and self._proc.state() != QProcess.ProcessState.NotRunning)


# --------------------------------------------------------------------------- #
# Task manager
# --------------------------------------------------------------------------- #
class TaskManager:
    """Owns the thread pool and keeps strong references to active runners."""

    def __init__(self, max_threads: int | None = None) -> None:
        self._pool = QThreadPool.globalInstance()
        if max_threads:
            self._pool.setMaxThreadCount(max_threads)
        self._runners: list[CommandRunner] = []
        _LOG.debug("TaskManager using up to %d threads", self._pool.maxThreadCount())

    def submit(self, fn: Callable[..., Any], *args: Any, **kwargs: Any) -> Worker:
        """Schedule *fn* on the pool and return the :class:`Worker` for signal wiring."""
        worker = Worker(fn, *args, **kwargs)
        self._pool.start(worker)
        return worker

    def track(self, runner: CommandRunner) -> CommandRunner:
        """Keep a reference to *runner* until its process finishes."""
        self._runners.append(runner)
        runner.finished.connect(lambda _code, r=runner: self._untrack(r))
        runner.failed.connect(lambda _msg, r=runner: self._untrack(r))
        return runner

    def _untrack(self, runner: CommandRunner) -> None:
        if runner in self._runners:
            self._runners.remove(runner)

    def run_command(self, program: str, arguments: Sequence[str]) -> CommandRunner:
        """Convenience: build, track, and start a :class:`CommandRunner`."""
        runner = self.track(CommandRunner())
        runner.start(program, arguments)
        return runner

    def cancel_all(self) -> None:
        for runner in list(self._runners):
            runner.cancel()

    def active_count(self) -> int:
        return self._pool.activeThreadCount()
