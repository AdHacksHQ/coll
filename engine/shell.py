"""Safe subprocess + helpers. argv-only, no shell=True, shlex-quoted reproduction."""
import re
import shlex
import subprocess


def slug(s: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-")
    return s[:60] or "item"


def run(argv, timeout=60, input_bytes=None):
    """Run argv safely. Returns (returncode, stdout:bytes, stderr:bytes, cmd:str)."""
    cmd = " ".join(shlex.quote(str(a)) for a in argv)
    try:
        r = subprocess.run(argv, capture_output=True, timeout=timeout, input=input_bytes)
        return r.returncode, r.stdout, r.stderr, cmd
    except subprocess.TimeoutExpired:
        return -1, b"", ("TIMEOUT after %ds" % timeout).encode(), cmd
    except FileNotFoundError:
        return -1, b"", b"command not found", cmd
    except Exception as e:  # noqa: BLE001 — boundary, never crash the lane
        return -1, b"", str(e).encode(), cmd
