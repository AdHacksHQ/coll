"""Lane T — live process runtime tracing via lldb.

Attach the free, installed Apple debugger (lldb) to a running process and pull
a live stack trace — the runtime counterpart to Lane A's static Mach-O reads.

Everything runs non-interactively through `lldb --batch`; no GUI, no pip
packages, no license. Reproduction command is always carried alongside output.

macOS reality (stated, never papered over):
  - lldb CAN attach to user-launched processes (same uid) and grab a backtrace.
  - lldb CANNOT attach to Apple-signed / hardened-runtime processes under SIP:
    `task_for_pid` is denied and the attach fails with "unable to find process"
    or an errno 5 / `eacces` style error. This lane detects that and offers a
    launch-under-debugger fallback (`lldb --batch -- <exe> ...`) instead of
    fighting the OS.
"""
from __future__ import annotations

import re

from .shell import run

_THREAD = re.compile(r"^\s*\*?\s*thread\s+#")
_FRAME = re.compile(r"^\s*\*?\s*frame\s+#")
_STOP_REASON = re.compile(r"stop reason\s*=\s*(.+)$")

# signals that the attach itself was refused by the OS (SIP/hardened runtime)
_ATTACH_DENIED = (
    "not allowed to attach",
    "unable to find process",
    "unable to find task",
    "error: attach failed",
    "task_for_pid",
    "not permitted",
    "operation not permitted",
    "eacces",
    "errno = 5",
)


def _lldb_available() -> bool:
    rc, _, _, _ = run(["lldb", "--version"], timeout=30)
    return rc == 0


def _parse_backtrace(text: str) -> dict:
    """Split raw lldb output into threads, frames, and a stop reason."""
    threads, frames, reason = [], [], None
    current = None
    for line in text.splitlines():
        m = _STOP_REASON.search(line)
        if m and reason is None:
            reason = m.group(1).strip()
        if _THREAD.match(line):
            current = line.strip()
            threads.append(current)
        elif _FRAME.match(line):
            f = line.strip()
            frames.append(f)
    return {"threads": threads, "frames": frames, "stop_reason": reason}


def _attach_denied(err: bytes) -> bool:
    low = err.decode("utf-8", "replace").lower()
    return any(tok in low for tok in _ATTACH_DENIED)


def backtrace(pid: int, all_threads: bool = True, timeout: int = 90) -> dict:
    """Attach lldb to a live PID and capture its stack.

    Returns a report dict keyed by mode/path plus the raw backtrace text and a
    parsed frame/thread summary. Never raises; failures land in report["error"].
    """
    report = {
        "lane": "trace",
        "mode": "attach",
        "pid": int(pid),
        "path": None,
        "returncode": None,
        "command": "",
        "backtrace": "",
        "summary": {},
        "error": None,
        "limitation": "SIP/hardened processes deny task_for_pid; see .limitation",
    }
    if not _lldb_available():
        report["error"] = "lldb not found on PATH"
        report["limitation"] = "lldb unavailable — lane cannot trace without it"
        return report

    bt_cmd = "thread backtrace all" if all_threads else "thread backtrace"
    argv = ["lldb", "--batch", "-p", str(pid),
            "-o", bt_cmd, "-o", "detach", "-o", "quit"]
    rc, out, err, cmd = run(argv, timeout=timeout)
    report["command"] = cmd
    report["returncode"] = rc

    text = (out + b"\n" + err).decode("utf-8", "replace")
    report["backtrace"] = text
    report["summary"] = _parse_backtrace(text)

    if rc != 0 or not text.strip():
        denied = _attach_denied(err)
        report["error"] = ("attach denied by SIP/hardened runtime" if denied
                           else f"lldb exited {rc} with no backtrace")
        report["limitation"] = (
            "attach refused (task_for_pid denied): process is Apple-signed/"
            "hardened or SIP-protected — retry with launch-under-debugger "
            "backtrace_launch()") if denied else \
            "lldb could not attach; see error"
        return report
    return report


def breakpoint_at(pid: int, symbol: str, all_threads: bool = True,
                  timeout: int = 120) -> dict:
    """Attach to a live PID, set a breakpoint on `symbol`, continue, and grab
    the stack when (if) it is hit. Blocks until the breakpoint fires or the
    batch timeout lapses."""
    report = {
        "lane": "trace",
        "mode": "attach-breakpoint",
        "pid": int(pid),
        "symbol": symbol,
        "path": None,
        "returncode": None,
        "command": "",
        "backtrace": "",
        "summary": {},
        "error": None,
        "limitation": "",
    }
    if not _lldb_available():
        report["error"] = "lldb not found on PATH"
        report["limitation"] = "lldb unavailable"
        return report

    bt_cmd = "thread backtrace all" if all_threads else "thread backtrace"
    argv = ["lldb", "--batch", "-p", str(pid),
            "-o", f"breakpoint set --name {symbol}",
            "-o", "continue",
            "-o", bt_cmd, "-o", "detach", "-o", "quit"]
    rc, out, err, cmd = run(argv, timeout=timeout)
    report["command"] = cmd
    report["returncode"] = rc

    text = (out + b"\n" + err).decode("utf-8", "replace")
    report["backtrace"] = text
    report["summary"] = _parse_backtrace(text)

    if rc != 0 or not text.strip():
        denied = _attach_denied(err)
        report["error"] = ("attach denied by SIP/hardened runtime" if denied
                           else f"lldb exited {rc}; breakpoint may not have hit")
        report["limitation"] = (
            "attach refused (task_for_pid denied) — launch-under-debugger "
            "required") if denied else "breakpoint did not hit within timeout"
        return report
    return report


def backtrace_launch(executable: str, args: list[str] | None = None,
                     symbol: str | None = None, all_threads: bool = True,
                     timeout: int = 120) -> dict:
    """Launch a program under lldb and capture its stack — the fallback for
    processes that refuse attach (SIP/hardened). Optionally breaks on `symbol`.

    `executable` is resolved on PATH when it is a bare name. The batch command
    list mirrors the attach path but uses `run` instead of `-p <pid>`.
    """
    report = {
        "lane": "trace",
        "mode": "launch",
        "pid": None,
        "path": executable,
        "returncode": None,
        "command": "",
        "backtrace": "",
        "summary": {},
        "error": None,
        "limitation": "launch-under-debugger only works on binaries you may exec",
    }
    if not _lldb_available():
        report["error"] = "lldb not found on PATH"
        report["limitation"] = "lldb unavailable"
        return report

    args = list(args or [])
    bt_cmd = "thread backtrace all" if all_threads else "thread backtrace"
    argv = ["lldb", "--batch"]
    if symbol:
        # run until the breakpoint hits, then capture the stack there
        argv += ["-o", f"breakpoint set --name {symbol}",
                 "-o", "run", "-o", bt_cmd, "-o", "quit"]
    else:
        # stop at entry so the stack is alive for the backtrace (a program
        # that runs to completion would otherwise exit before `bt` runs)
        argv += ["-o", "process launch --stop-at-entry",
                 "-o", bt_cmd, "-o", "quit"]
    argv += ["--", executable] + args
    rc, out, err, cmd = run(argv, timeout=timeout)
    report["command"] = cmd
    report["returncode"] = rc

    text = (out + b"\n" + err).decode("utf-8", "replace")
    report["backtrace"] = text
    report["summary"] = _parse_backtrace(text)

    if rc != 0 or not text.strip():
        denied = _attach_denied(err)
        report["error"] = ("launch refused by SIP/hardened runtime (Apple-signed "
                           "binary)" if denied
                           else f"lldb exited {rc}; no backtrace captured")
        report["limitation"] = (
            "Apple-signed / hardened binaries deny debugging under SIP — use a "
            "user-built (adhoc/unsigned) binary, or attach to a running user "
            "process instead") if denied else "lldb launch produced no backtrace"
        return report
    return report


def trace(target, symbol: str | None = None, all_threads: bool = True,
          timeout: int = 120) -> dict:
    """Unified entry: `target` is an int PID (attach) or a str executable
    (launch-under-debugger). Picks the path and normalizes the report shape."""
    if isinstance(target, int):
        if symbol:
            return breakpoint_at(target, symbol, all_threads, timeout)
        return backtrace(target, all_threads, timeout)
    if isinstance(target, str):
        return backtrace_launch(target, symbol=symbol,
                                all_threads=all_threads, timeout=timeout)
    return {"lane": "trace", "error": "target must be an int PID or str executable"}
