"""Lane L — ELF binary inspection (linux lane).

Uses the installed free LLVM toolchain (file, llvm-objdump/objdump, nm, strings)
to surface: binary identity, architecture, linked (NEEDED) shared objects,
symbol surface, and a strings signal. Static only — nothing is executed.

Every finding ships its exact reproduction command and a blake2b digest via
bank.add(); confidence and limitations are stated, never papered over.
"""
from __future__ import annotations

import os
import re

from .shell import run, slug

_NEEDED = re.compile(r"NEEDED\s+(.+)")
_ARCH = re.compile(r"architecture:\s*(.+)")
_START = re.compile(r"start address:\s*(0x[0-9a-fA-F]+)")

_URL = re.compile(r"https?://[^\s\"'<>]+")
_API_PATH = re.compile(r"^/(?:api|v\d+|graphql|rest|oauth)[/\w.-]*$", re.I)
_FLAG = re.compile(r"^(?:feature|experiment|enable|disable|use)[_.-][a-z0-9_.-]+$", re.I)
_ABS_PATH = re.compile(r"^/(?:usr|etc|opt|home|var|srv|lib|bin|sbin)[/\w.-]*$")
_SO_REF = re.compile(r"\w[\w.+-]*\.so(?:\.\d+)*", re.I)


def _objdump() -> str:
    for name in ("llvm-objdump", "objdump"):
        rc, _, _, _ = run([name, "--version"], timeout=10)
        if rc == 0:
            return name
    return "llvm-objdump"


def _parse_nm(text: str) -> dict:
    defined = undefined = weak = other = 0
    names = set()
    for line in text.splitlines():
        line = line.rstrip()
        if not line:
            continue
        toks = line.split()
        if len(toks) < 2:
            continue
        name = toks[-1]
        typ = None
        for t in toks[-2::-1]:  # scan right-to-left for a single-char type
            if len(t) == 1 and (t.isalpha() or t in "?@"):
                typ = t
                break
        if typ in ("U", "u"):
            undefined += 1
        elif typ in ("W", "w", "V", "v"):
            weak += 1
        elif typ == "?":
            other += 1
        elif typ is not None:
            defined += 1
        names.add(name)
    return {
        "symbols": len(names),
        "defined": defined,
        "undefined": undefined,
        "weak": weak,
        "sample": sorted(names)[:60],
    }


def _strings_signal(path: str, bank, lane: str, extras: dict, cap_artifact=6_000_000) -> tuple:
    rc, out, _, cmd = run(["strings", "-", path], timeout=240)
    if rc != 0:
        return {"error": "strings failed"}, cmd
    text = out.decode("utf-8", "replace")
    lines = text.splitlines()
    urls = sorted({m.group(0).rstrip(").,") for m in _URL.finditer(text)})[:60]
    apis = set()
    flags = set()
    extra_hits = set()
    for ln in lines:
        ln = ln.strip()
        if 2 <= len(ln) <= 200:
            if _API_PATH.match(ln):
                apis.add(ln)
            elif _FLAG.match(ln):
                flags.add(ln)
            for label, pat in extras.items():
                if pat.search(ln):
                    extra_hits.add(ln[:120])
    artifact = out[:cap_artifact]
    bank.add(lane, path, "strings (bounded)", "strings", cmd, artifact,
             {"total_lines": len(lines), "bounded": len(artifact) < len(out)},
             limitation="strings is heuristic; URLs/paths/flags are inferred, not resolved")
    return {
        "urls": urls,
        "api_paths": sorted(apis)[:60],
        "feature_flags": sorted(flags)[:40],
        "library_paths": sorted(extra_hits)[:60],
    }, cmd


def inspect_linux(target: str, bank) -> dict:
    target = os.path.abspath(target)
    report: dict = {"target": target, "lane": "linux"}

    if not os.path.isfile(target):
        report["error"] = f"no such file: {target}"
        return report

    rc, ft, _, cmd = run(["file", "-b", target], timeout=20)
    fmt = ft.decode("utf-8", "replace").strip() if rc == 0 else ""
    report["format"] = fmt
    bank.add("linux", target, "binary identity (file -b)", "file", cmd, ft,
             {"format": fmt},
             limitation="file magic is authoritative for the container, not internal structure")
    if "ELF" not in fmt:
        report["error"] = f"not an ELF binary: {fmt or 'unrecognized'}"
        return report

    od = _objdump()

    rc, fh, _, cmd = run([od, "-f", target], timeout=60)
    arch = ""
    entry = None
    if rc == 0:
        ftext = fh.decode("utf-8", "replace")
        m = _ARCH.search(ftext)
        arch = m.group(1).strip() if m else ""
        m = _START.search(ftext)
        entry = m.group(1) if m else None
    report["arch"] = arch
    report["entry_point"] = entry

    rc, op, oerr, cmd = run([od, "-p", target], timeout=60)
    needed = []
    if rc == 0:
        ptext = op.decode("utf-8", "replace")
        for line in ptext.splitlines():
            m = _NEEDED.search(line)
            if m:
                needed.append(m.group(1).strip())
        needed = sorted(set(needed))
        bank.add("linux", target, "dynamic section (objdump -p)", od, cmd, op,
                 {"needed_libs": len(needed)},
                 limitation="NEEDED lists direct deps only; transitive resolution is the loader's job")
    else:
        bank.add("linux", target, "dynamic section (objdump -p)", od, cmd,
                 oerr or b"objdump -p failed", {"needed_libs": 0},
                 confidence="unknown",
                 limitation=oerr.decode("utf-8", "replace")[:200])
    report["linked_libs"] = needed

    rc, no, nerr, cmd = run(["nm", target], timeout=120)
    if rc == 0:
        surf = _parse_nm(no.decode("utf-8", "replace"))
        bank.add("linux", target, "symbol surface (nm)", "nm", cmd, no, surf,
                 limitation="symbols only; stripped binaries yield far less")
    else:
        surf = {"symbols": 0, "note": "nm failed"}
        bank.add("linux", target, "symbol surface (nm)", "nm", cmd,
                 nerr or b"nm failed", surf, confidence="unknown",
                 limitation=nerr.decode("utf-8", "replace")[:200])
    report["symbol_surface"] = surf

    extras = {"shared_objects": _SO_REF, "absolute_paths": _ABS_PATH}
    strsig, _ = _strings_signal(target, bank, "linux", extras)
    report["strings_signal"] = strsig

    return report
