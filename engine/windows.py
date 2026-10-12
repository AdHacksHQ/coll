"""Lane P — PE/Windows binary inspection (windows lane).

Uses the installed free LLVM toolchain (file, llvm-objdump/objdump, nm, strings)
to surface: binary identity, architecture, imported DLLs + imported functions,
symbol table (when present), and a strings signal. Static only — nothing runs.

Every finding ships its exact reproduction command and a blake2b digest via
bank.add(); confidence and limitations are stated, never papered over.
"""
from __future__ import annotations

import os
import re

from .shell import run, slug

_DLL_NAME = re.compile(r"DLL Name:\s*(.+)")
_IMP_FN = re.compile(r"^\s+\d+\s+([A-Za-z_][A-Za-z0-9_@?$]*)$")
_ARCH = re.compile(r"architecture:\s*(.+)")
_ENTRY = re.compile(r"AddressOfEntryPoint\s+(0x[0-9a-fA-F]+)")
_SUBSYSTEM = re.compile(r"Subsystem\s+([0-9a-fA-F]+)\s+\(([^)]+)\)")

_URL = re.compile(r"https?://[^\s\"'<>]+")
_API_PATH = re.compile(r"^/(?:api|v\d+|graphql|rest|oauth)[/\w.-]*$", re.I)
_FLAG = re.compile(r"^(?:feature|experiment|enable|disable|use)[_.-][a-z0-9_.-]+$", re.I)
_DLL_REF = re.compile(r"\w[\w.+-]*\.dll", re.I)
_REGKEY = re.compile(r"(?:HKLM|HKCU|HKCR|HKU|HKCC|HKPD)[\\\w\s.{}%-]{3,}", re.I)


def _objdump() -> str:
    for name in ("llvm-objdump", "objdump"):
        rc, _, _, _ = run([name, "--version"], timeout=10)
        if rc == 0:
            return name
    return "llvm-objdump"


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
             limitation="strings is heuristic; URLs/flags/DLL refs are inferred, not resolved")
    return {
        "urls": urls,
        "api_paths": sorted(apis)[:60],
        "feature_flags": sorted(flags)[:40],
        "dll_registry": sorted(extra_hits)[:60],
    }, cmd


def inspect_windows(target: str, bank) -> dict:
    target = os.path.abspath(target)
    report: dict = {"target": target, "lane": "windows"}

    if not os.path.isfile(target):
        report["error"] = f"no such file: {target}"
        return report

    rc, ft, _, cmd = run(["file", "-b", target], timeout=20)
    fmt = ft.decode("utf-8", "replace").strip() if rc == 0 else ""
    report["format"] = fmt
    bank.add("windows", target, "binary identity (file -b)", "file", cmd, ft,
             {"format": fmt},
             limitation="file magic is authoritative for the container, not internal structure")
    if not ("PE32" in fmt or "MS Windows" in fmt or "PE32+" in fmt):
        report["error"] = f"not a PE/Windows binary: {fmt or 'unrecognized'}"
        return report

    od = _objdump()

    rc, fh, _, cmd = run([od, "-f", target], timeout=60)
    arch = ""
    if rc == 0:
        m = _ARCH.search(fh.decode("utf-8", "replace"))
        arch = m.group(1).strip() if m else ""
    report["arch"] = arch

    rc, op, oerr, cmd = run([od, "-p", target], timeout=120)
    dlls = set()
    imports = set()
    entry = None
    subsystem = None
    if rc == 0:
        ptext = op.decode("utf-8", "replace")
        m = _ENTRY.search(ptext)
        entry = m.group(1) if m else None
        m = _SUBSYSTEM.search(ptext)
        subsystem = m.group(2) if m else None
        for line in ptext.splitlines():
            m = _DLL_NAME.search(line)
            if m:
                dlls.add(m.group(1).strip())
                continue
            m = _IMP_FN.match(line)
            if m:
                imports.add(m.group(1))
        bank.add("windows", target, "PE headers + imports (objdump -p)", od, cmd, op,
                 {"imported_dlls": len(dlls), "imported_functions": len(imports)},
                 limitation="import table is a direct-dependency view; delay-loaded and runtime LoadLibrary calls are invisible")
    else:
        bank.add("windows", target, "PE headers + imports (objdump -p)", od, cmd,
                 oerr or b"objdump -p failed", {"imported_dlls": 0, "imported_functions": 0},
                 confidence="unknown", limitation=oerr.decode("utf-8", "replace")[:200])
    report["entry_point"] = entry
    report["subsystem"] = subsystem
    report["imported_dlls"] = sorted(dlls)
    report["imported_symbols"] = sorted(imports)[:120]
    report["import_count"] = len(imports)

    rc, no, nerr, cmd = run(["nm", target], timeout=120)
    if rc == 0 and no.strip():
        names = sorted({toks[-1] for ln in no.decode("utf-8", "replace").splitlines()
                        if (toks := ln.split()) and len(toks) >= 2})
        surf = {"symbols": len(names), "sample": names[:60]}
        bank.add("windows", target, "symbol table (nm)", "nm", cmd, no, surf,
                 limitation="symbols only when the PE ships a symbol table")
    else:
        surf = {"symbols": 0, "note": "no symbol table (stripped PE; imports above carry the surface)"}
        bank.add("windows", target, "symbol table (nm)", "nm", cmd,
                 no or nerr or b"nm yielded no symbols", surf, confidence="unknown",
                 limitation="most shipped PEs are stripped; llvm-nm yields no symbol table")
    report["symbol_surface"] = surf

    extras = {"dll_refs": _DLL_REF, "registry_keys": _REGKEY}
    strsig, _ = _strings_signal(target, bank, "windows", extras)
    report["strings_signal"] = strsig

    return report
