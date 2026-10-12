"""Lane U — generic non-Mach-O Unix binary inspection (unix lane).

Catch-all for object/executable formats that are not Mach-O and not covered
by the ELF or PE lanes (COFF, a.out, ar archives, core dumps, relocatable
objects, ...). Best-effort: identity via `file`, arch via objdump -f, symbols
via nm, strings signal — each tool degrades cleanly when it cannot parse the
container. Static only; nothing runs.

Every finding ships its exact reproduction command and a blake2b digest via
bank.add(); confidence and limitations are stated, never papered over.
"""
from __future__ import annotations

import os
import re

from .shell import run, slug

_ARCH = re.compile(r"architecture:\s*(.+)")

_URL = re.compile(r"https?://[^\s\"'<>]+")
_API_PATH = re.compile(r"^/(?:api|v\d+|graphql|rest|oauth)[/\w.-]*$", re.I)
_FLAG = re.compile(r"^(?:feature|experiment|enable|disable|use)[_.-][a-z0-9_.-]+$", re.I)
_LIB_REF = re.compile(r"\w[\w.+-]*\.(?:so|dll|dylib)(?:\.\d+)*", re.I)
_ABS_PATH = re.compile(r"^/(?:usr|etc|opt|home|var|srv|lib|bin|sbin)[/\w.-]*$")


def _objdump() -> str:
    for name in ("llvm-objdump", "objdump"):
        rc, _, _, _ = run([name, "--version"], timeout=10)
        if rc == 0:
            return name
    return "llvm-objdump"


def _parse_nm(text: str) -> dict:
    defined = undefined = 0
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
        for t in toks[-2::-1]:
            if len(t) == 1 and (t.isalpha() or t in "?@"):
                typ = t
                break
        if typ in ("U", "u"):
            undefined += 1
        elif typ is not None:
            defined += 1
        names.add(name)
    return {
        "symbols": len(names),
        "defined": defined,
        "undefined": undefined,
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


def inspect_unix(target: str, bank) -> dict:
    target = os.path.abspath(target)
    report: dict = {"target": target, "lane": "unix"}

    if not os.path.isfile(target):
        report["error"] = f"no such file: {target}"
        return report

    rc, ft, _, cmd = run(["file", "-b", target], timeout=20)
    fmt = ft.decode("utf-8", "replace").strip() if rc == 0 else ""
    report["format"] = fmt
    bank.add("unix", target, "binary identity (file -b)", "file", cmd, ft,
             {"format": fmt},
             limitation="file magic is authoritative for the container, not internal structure")
    if "Mach-O" in fmt or "PE32" in fmt or "ELF" in fmt:
        report["error"] = (f"not a generic unix binary — recognized as "
                           f"{'Mach-O' if 'Mach-O' in fmt else 'PE' if 'PE32' in fmt else 'ELF'}: {fmt}")
        return report

    od = _objdump()

    rc, fh, _, cmd = run([od, "-f", target], timeout=60)
    arch = ""
    if rc == 0:
        m = _ARCH.search(fh.decode("utf-8", "replace"))
        arch = m.group(1).strip() if m else ""
        bank.add("unix", target, "file header (objdump -f)", od, cmd, fh,
                 {"arch": arch}, limitation="objdump -f may not parse every unix object format")
    else:
        bank.add("unix", target, "file header (objdump -f)", od, cmd,
                 fh or b"objdump -f failed", {"arch": ""}, confidence="unknown",
                 limitation=fh.decode("utf-8", "replace")[:200] if fh else "objdump -f failed")
    report["arch"] = arch

    rc, no, nerr, cmd = run(["nm", target], timeout=120)
    if rc == 0 and no.strip():
        surf = _parse_nm(no.decode("utf-8", "replace"))
        bank.add("unix", target, "symbol surface (nm)", "nm", cmd, no, surf,
                 limitation="symbols only; archives/relocatables may need per-member nm")
    else:
        surf = {"symbols": 0, "note": "nm yielded no symbols for this container"}
        bank.add("unix", target, "symbol surface (nm)", "nm", cmd,
                 no or nerr or b"nm yielded no symbols", surf, confidence="unknown",
                 limitation="nm cannot symbolize every unix object format")
    report["symbol_surface"] = surf

    extras = {"library_refs": _LIB_REF, "absolute_paths": _ABS_PATH}
    strsig, _ = _strings_signal(target, bank, "unix", extras)
    report["strings_signal"] = strsig

    return report
