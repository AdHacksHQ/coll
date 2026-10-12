"""Lane A — macOS .app / Mach-O inspection.

Apple-native: uses the installed free toolchain (otool, nm, objdump, lipo, file,
plutil, codesign, strings, xcrun swift-demangle). No Hopper/Ghidra/IDA license.
"""
from __future__ import annotations

import os
import plistlib
import re
from collections import Counter

from .shell import run, slug

# interesting Info.plist keys -> human labels
PLIST_KEYS = [
    "CFBundleIdentifier", "CFBundleName", "CFBundleDisplayName",
    "CFBundleShortVersionString", "CFBundleVersion", "CFBundleExecutable",
    "CFBundlePackageType", "LSMinimumSystemVersion", "CFBundleSupportedPlatforms",
    "NSPrincipalClass", "NSMainNibFile", "CFBundleURLTypes", "CFBundleDocumentTypes",
    "NSAppTransportSecurity", "LSApplicationCategoryType", "CFBundleIconFile",
]

_OBJC_CLASS = re.compile(r"^_OBJC_CLASS_\$_(.+)$")
_OBJC_META = re.compile(r"^_OBJC_METACLASS_\$_(.+)$")
_OBJC_PROTO = re.compile(r"^_OBJC_PROTOCOL_\$_(.+)$")
_OBJC_CAT = re.compile(r"^_OBJC_\$_CATEGORY_(.+)_\$_(.+)$")
_SWIFT = re.compile(r"^_\$[sS]")   # Mach-O Swift mangling: _$s / _$S

_URL = re.compile(r"https?://[^\s\"'<>]+")
_API_PATH = re.compile(r"^/(?:api|v\d+|graphql|rest|oauth)[/\w.-]*$", re.I)
_SELECTOR = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]*(?::[a-zA-Z0-9_]+)*:$")
_FLAG = re.compile(r"^(?:feature|experiment|enable|disable|use)[_.-][a-z0-9_.-]+$", re.I)


def _is_macho(path: str) -> bool:
    if not os.path.isfile(path):
        return False
    rc, out, _, _ = run(["file", "-b", path], timeout=20)
    return rc == 0 and b"Mach-O" in out


def _collect_binaries(app_root: str) -> list[str]:
    bins = []
    for dirpath, dirnames, filenames in os.walk(app_root):
        dirnames[:] = [d for d in dirnames if d not in {".git", "node_modules"}]
        for fn in filenames:
            p = os.path.join(dirpath, fn)
            if os.path.islink(p):
                continue
            if _is_macho(p):
                bins.append(p)
    return bins


def _info_plist(app_root: str):
    pl = os.path.join(app_root, "Contents", "Info.plist")
    if not os.path.exists(pl):
        return None, None
    with open(pl, "rb") as f:
        data = plistlib.load(f)
    return pl, data


def _entitlements(binpath: str):
    rc, out, err, cmd = run(["codesign", "-d", "--entitlements", ":-", binpath], timeout=30)
    if rc != 0 or not out.strip():
        return None, cmd
    try:
        return plistlib.loads(out), cmd
    except Exception:
        return {"raw": out.decode("utf-8", "replace")}, cmd


def _symbol_surface(binpath: str):
    """Classify external symbols into ObjC classes/protocols/categories + Swift count."""
    rc, out, _, cmd = run(["nm", "-gj", binpath], timeout=120)
    if rc != 0:
        return {"error": "nm failed"}, cmd, b""
    text = out.decode("utf-8", "replace")
    classes, protos, cats, swift = set(), set(), set(), 0
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        m = _OBJC_CLASS.match(line)
        if m:
            classes.add(m.group(1))
            continue
        m = _OBJC_PROTO.match(line)
        if m:
            protos.add(m.group(1))
            continue
        m = _OBJC_CAT.match(line)
        if m:
            cats.add(f"{m.group(1)} ({m.group(2)})")
            continue
        if _SWIFT.match(line):
            swift += 1
    return {
        "objc_classes": len(classes),
        "objc_protocols": len(protos),
        "objc_categories": len(cats),
        "swift_symbols": swift,
        "class_sample": sorted(classes)[:40],
    }, cmd, out


def _demangle_swift(symbols: list[str]) -> list[str]:
    """Demangle a capped sample of Swift symbols in one batch via xcrun."""
    if not symbols:
        return []
    joined = ("\n".join(symbols) + "\n").encode()
    rc, out, _, _ = run(["xcrun", "swift-demangle", "--compact"], timeout=60, input_bytes=joined)
    if rc != 0:
        return []
    return [l for l in out.decode("utf-8", "replace").splitlines() if l and not l.startswith("_$s")]


def _strings_signal(binpath: str, bank, cap_artifact=6_000_000):
    """Extract feature-relevant strings: selectors, URLs, API paths, flags."""
    rc, out, _, cmd = run(["strings", "-", binpath], timeout=120)
    if rc != 0:
        return {"error": "strings failed"}, cmd
    text = out.decode("utf-8", "replace")
    lines = text.splitlines()
    urls = sorted({m.group(0).rstrip(").,") for m in _URL.finditer(text)})[:80]
    selectors = set()
    apis = set()
    flags = set()
    for ln in lines:
        ln = ln.strip()
        if 2 <= len(ln) <= 160:
            if _SELECTOR.match(ln):
                selectors.add(ln)
            elif _API_PATH.match(ln):
                apis.add(ln)
            elif _FLAG.match(ln):
                flags.add(ln)
    # save a bounded artifact (full strings can be tens of MB)
    artifact = out[:cap_artifact]
    bank.add("apple", binpath, "strings (bounded)", "strings", cmd, artifact,
             {"total_lines": len(lines), "bounded": len(artifact) < len(out)},
             limitation="strings is heuristic; selectors/URLs/flags are inferred, not resolved")
    return {
        "urls": urls,
        "selectors": sorted(selectors)[:120],
        "selector_count": len(selectors),
        "api_paths": sorted(apis)[:80],
        "feature_flags": sorted(flags)[:60],
    }, cmd


def inspect_apple(target: str, bank, max_extra_binaries: int = 12) -> dict:
    target = os.path.abspath(target)
    if target.endswith(".app") or os.path.exists(os.path.join(target, "Contents")):
        app_root = target if target.endswith(".app") else target
    else:
        app_root = None
    report = {"target": target, "lane": "apple", "app_bundle": bool(app_root)}

    if app_root:
        pl_path, data = _info_plist(app_root)
        if pl_path:
            rc, raw, _, cmd = run(["plutil", "-p", pl_path], timeout=20)
            bank.add("apple", target, "Info.plist (raw)", "plutil", cmd, raw)
            facts = {k: data.get(k) for k in PLIST_KEYS if k in data}
            report["info_plist"] = facts

        bins = _collect_binaries(app_root)
        if bins and data and data.get("CFBundleExecutable"):
            main = os.path.join(app_root, "Contents", "MacOS", data["CFBundleExecutable"])
            bins.sort(key=lambda b: 0 if b == main else 1)
        report["binary_count"] = len(bins)
    else:
        bins = [target] if _is_macho(target) else []

    binary_inventory = []
    primary_surface = None
    for i, b in enumerate(bins):
        if i >= max_extra_binaries:
            report["binary_inventory_truncated"] = len(bins) - max_extra_binaries
            break
        rel = os.path.relpath(b, app_root) if app_root else os.path.basename(b)
        _, ft, _, _ = run(["file", "-b", b], timeout=20)
        _, arch, _, _ = run(["lipo", "-info", b], timeout=20)
        rc, libs, _, cmd = run(["otool", "-L", b], timeout=60)
        lib_lines = [l.strip() for l in libs.decode("utf-8", "replace").splitlines()[1:] if l.strip()]
        inv = {
            "path": rel,
            "type": ft.decode("utf-8", "replace").strip(),
            "arch": arch.decode("utf-8", "replace").strip(),
            "linked_libs": lib_lines,
        }
        if i == 0:
            # primary binary: deep symbol + string analysis
            surf, scmd, nout = _symbol_surface(b)
            bank.add("apple", rel, "symbol surface (nm -gj)", "nm", scmd, nout, surf,
                     limitation="undefined/external symbols only; stripped bins yield less")
            if surf.get("swift_symbols", 0):
                # demangle a sample of Swift symbols
                rc2, nout2, _, cmd2 = run(["nm", "-gj", b], timeout=120)
                syms = [l for l in nout2.decode("utf-8", "replace").splitlines()
                        if _SWIFT.match(l.strip())][:300]
                dem = _demangle_swift(syms)
                surf["swift_sample"] = dem[:60]
                bank.add("apple", rel, "swift demangle sample", "xcrun swift-demangle", cmd2,
                         "\n".join(dem).encode(), {"sample": len(dem)})
            primary_surface = surf
            inv["symbol_surface"] = surf
        binary_inventory.append(inv)

    report["binaries"] = binary_inventory

    if primary_surface is not None and bins:
        strsig, _ = _strings_signal(bins[0], bank)
        report["strings_signal"] = strsig

    # entitlements + signature on the main binary
    if bins:
        ent, ecmd = _entitlements(bins[0])
        if ent is not None:
            bank.add("apple", target, "entitlements", "codesign", ecmd,
                     plistlib.dumps(ent) if not isinstance(ent, dict) or "raw" not in ent
                     else ent.get("raw", "").encode(), ent)
            report["entitlements"] = ent
        rc, so, se, scmd = run(["codesign", "-dv", "--verbose=2", bins[0]], timeout=30)
        if rc == 0:
            report["codesign"] = (so + b"\n" + se).decode("utf-8", "replace").strip()

    return report
