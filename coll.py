#!/usr/bin/env python3
"""Coll — reverse-engineer a feature from an app, our way.

Usage:
  python3 coll.py <target> [--lane auto|apple|electron|web|linux|windows|unix] [--out DIR]

Lanes:
  apple    — macOS .app / Mach-O (Info.plist, entitlements, symbols, strings)
  electron — Electron/JS bundle (asar, module graph, IPC, routes)
  web      — web app / SPA surface (frameworks, routes, APIs, analytics)
  linux    — ELF binaries (identity, arch, NEEDED libs, symbols, strings)
  windows  — PE binaries (identity, arch, imported DLLs/functions, strings)
  unix     — generic non-Mach-O Unix binaries (best-effort object scan)

Findings print concisely to stdout; full evidence + a verifiable manifest
land in --out. Nothing is executed from the target; analysis is static.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from engine import EvidenceBank
from engine import apple, electron, web, linux, windows, unix
from engine import run

_OBJECT_RE = re.compile(
    r"object|executable|shared library|relocatable|archive|core file|COFF|a\.out",
    re.I,
)


def _file_type(path: str) -> str:
    if not os.path.isfile(path):
        return ""
    rc, out, _, _ = run(["file", "-b", path], timeout=20)
    return out.decode("utf-8", "replace") if rc == 0 else ""


def detect_lane(target: str) -> str:
    if target.startswith(("http://", "https://")):
        return "web"
    t = os.path.abspath(target)
    if t.endswith(".asar"):
        return "electron"
    if t.endswith(".app") or os.path.exists(os.path.join(t, "Contents")):
        if os.path.exists(os.path.join(t, "Contents", "Resources", "app.asar")):
            return "electron"
        return "apple"
    if os.path.isdir(t):
        return "electron"
    # regular file: sniff the container format with `file`
    ft = _file_type(t)
    if "ELF" in ft:
        return "linux"
    if "PE32" in ft or "MS Windows" in ft:
        return "windows"
    if "Mach-O" in ft:
        return "apple"
    if _OBJECT_RE.search(ft):
        return "unix"
    return "apple"


def render(report: dict) -> str:
    out = []
    lane = report.get("lane")
    out.append(f"# Coll — {lane.upper()} — {report['target']}")

    if lane == "apple":
        if "info_plist" in report:
            out.append("\n## Bundle identity")
            for k, v in report["info_plist"].items():
                out.append(f"  {k}: {v}")
        if "entitlements" in report:
            out.append("\n## Entitlements")
            out.append(f"  {json.dumps(report['entitlements'], default=str)[:600]}")
        if "codesign" in report:
            out.append("\n## Signature")
            for line in report["codesign"].splitlines()[:6]:
                out.append(f"  {line}")
        out.append(f"\n## Binaries ({report.get('binary_count', 0)} total)")
        for b in report.get("binaries", [])[:4]:
            out.append(f"  - {b['path']}")
            out.append(f"      {b['arch']}")
            libs = [l for l in b.get("linked_libs", []) if l]
            out.append(f"      linked: {len(libs)} libs, e.g. {', '.join(libs[:4])}")
            s = b.get("symbol_surface")
            if s:
                out.append(f"      objc_classes={s.get('objc_classes')} "
                           f"protocols={s.get('objc_protocols')} "
                           f"categories={s.get('objc_categories')} "
                           f"swift_symbols={s.get('swift_symbols')}")
                if s.get("swift_sample"):
                    out.append(f"      swift types: {', '.join(s['swift_sample'][:8])}")
        if "strings_signal" in report:
            ss = report["strings_signal"]
            out.append(f"\n## Strings signal (selectors={ss.get('selector_count')})")
            out.append(f"  URLs: {', '.join(ss.get('urls', [])[:6])}")
            out.append(f"  API paths: {', '.join(ss.get('api_paths', [])[:10])}")
            out.append(f"  selectors: {', '.join(ss.get('selectors', [])[:15])}")
            out.append(f"  feature flags: {', '.join(ss.get('feature_flags', [])[:10])}")

    elif lane == "electron":
        if "asar" in report:
            out.append(f"\n## asar: {report['asar']} ({report.get('asar_file_count', '?')} files)")
        a = report.get("analysis")
        if a:
            if "package" in a:
                p = a["package"]
                out.append(f"\n## package: {p.get('name')} v{p.get('version')} (main={p.get('main')})")
                out.append(f"  deps: {', '.join(p.get('dependencies', [])[:12])}")
            out.append(f"\n## JS files analyzed: {a.get('js_files_analyzed')}")
            out.append(f"  external modules: {', '.join(f'{m}×{c}' for m, c in a.get('external_modules', [])[:20])}")
            out.append(f"\n## IPC main channels ({len(a.get('ipc_main_channels', []))})")
            out.append("  " + ", ".join(a["ipc_main_channels"][:40]))
            out.append(f"\n## IPC renderer channels ({len(a.get('ipc_renderer_channels', []))})")
            out.append("  " + ", ".join(a["ipc_renderer_channels"][:40]))
            out.append(f"\n## contextBridge exposures ({len(a.get('contextbridge_exposures', []))})")
            out.append("  " + ", ".join(a["contextbridge_exposures"][:40]))
            out.append(f"\n## routes ({len(a.get('routes', []))})")
            out.append("  " + ", ".join(a["routes"][:40]))
    elif lane == "web":
        if "error" in report:
            out.append(f"\n## error: {report['error']}")
        else:
            out.append(f"\n## page: {report.get('title')} (HTTP {report.get('http_status')})")
            fw = report.get("framework") or {}
            for name, v in fw.items():
                ver = v.get("version") if isinstance(v, dict) else None
                out.append(f"  framework: {name}" + (f" v{ver}" if ver else ""))
            out.append(f"\n## app bundles analyzed: {report.get('bundles_analyzed')}")
            out.append(f"  libraries: {', '.join(report.get('libraries', []))}")
            out.append(f"\n## routes ({len(report.get('routes', []))})")
            out.append("  " + ", ".join(report["routes"][:40]))
            out.append(f"\n## api endpoints ({len(report.get('api_endpoints', []))})")
            out.append("  " + ", ".join(report["api_endpoints"][:40]))
            out.append(f"\n## auth signals: {', '.join(report.get('auth_signals', []))}")
            out.append(f"\n## analytics ({len(report.get('analytics', []))})")
            for a in report.get("analytics", [])[:15]:
                out.append(f"  - {a}")
            out.append(f"\n## env config keys ({len(report.get('env_config_keys', []))})")
            out.append("  " + ", ".join(report["env_config_keys"][:40]))
            out.append(f"\n## domains ({len(report.get('domains', []))})")
            out.append("  " + ", ".join(report["domains"][:40]))
    elif lane == "linux":
        if "error" in report:
            out.append(f"\n## error: {report['error']}")
        else:
            out.append(f"\n## format: {report.get('format')}")
            if report.get("arch"):
                out.append(f"  arch: {report['arch']}")
            if report.get("entry_point"):
                out.append(f"  entry point: {report['entry_point']}")
            out.append(f"\n## linked libs ({len(report.get('linked_libs', []))})")
            out.append("  " + ", ".join(report["linked_libs"][:40]))
            s = report.get("symbol_surface") or {}
            out.append(f"\n## symbols: {s.get('symbols', 0)} "
                       f"(defined={s.get('defined', 0)} undefined={s.get('undefined', 0)} "
                       f"weak={s.get('weak', 0)})")
            if s.get("sample"):
                out.append("  sample: " + ", ".join(s["sample"][:20]))
            ss = report.get("strings_signal") or {}
            out.append("\n## strings signal")
            out.append(f"  URLs: {', '.join(ss.get('urls', [])[:6])}")
            out.append(f"  API paths: {', '.join(ss.get('api_paths', [])[:10])}")
            out.append(f"  feature flags: {', '.join(ss.get('feature_flags', [])[:10])}")
            out.append(f"  library paths: {', '.join(ss.get('library_paths', [])[:12])}")
    elif lane == "windows":
        if "error" in report:
            out.append(f"\n## error: {report['error']}")
        else:
            out.append(f"\n## format: {report.get('format')}")
            if report.get("arch"):
                out.append(f"  arch: {report['arch']}")
            if report.get("entry_point"):
                out.append(f"  entry point: {report['entry_point']}")
            if report.get("subsystem"):
                out.append(f"  subsystem: {report['subsystem']}")
            out.append(f"\n## imported DLLs ({len(report.get('imported_dlls', []))})")
            out.append("  " + ", ".join(report["imported_dlls"][:40]))
            out.append(f"\n## imported functions ({report.get('import_count', 0)})")
            out.append("  " + ", ".join(report.get("imported_symbols", [])[:40]))
            s = report.get("symbol_surface") or {}
            out.append(f"\n## symbol table: {s.get('symbols', 0)} ({s.get('note', '')})".rstrip())
            ss = report.get("strings_signal") or {}
            out.append("\n## strings signal")
            out.append(f"  URLs: {', '.join(ss.get('urls', [])[:6])}")
            out.append(f"  API paths: {', '.join(ss.get('api_paths', [])[:10])}")
            out.append(f"  feature flags: {', '.join(ss.get('feature_flags', [])[:10])}")
            out.append(f"  DLL/registry: {', '.join(ss.get('dll_registry', [])[:12])}")
    elif lane == "unix":
        if "error" in report:
            out.append(f"\n## error: {report['error']}")
        else:
            out.append(f"\n## format: {report.get('format')}")
            if report.get("arch"):
                out.append(f"  arch: {report['arch']}")
            s = report.get("symbol_surface") or {}
            out.append(f"\n## symbols: {s.get('symbols', 0)} "
                       f"(defined={s.get('defined', 0)} undefined={s.get('undefined', 0)})")
            if s.get("sample"):
                out.append("  sample: " + ", ".join(s["sample"][:20]))
            ss = report.get("strings_signal") or {}
            out.append("\n## strings signal")
            out.append(f"  URLs: {', '.join(ss.get('urls', [])[:6])}")
            out.append(f"  API paths: {', '.join(ss.get('api_paths', [])[:10])}")
            out.append(f"  feature flags: {', '.join(ss.get('feature_flags', [])[:10])}")
            out.append(f"  library paths: {', '.join(ss.get('library_paths', [])[:12])}")

    return "\n".join(out)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("target")
    ap.add_argument("--lane", choices=["auto", "apple", "electron", "web", "linux", "windows", "unix"], default="auto")
    ap.add_argument("--out", default=None,
                    help="evidence output dir (default: coll-out/<basename>)")
    ap.add_argument("--index", action="store_true",
                    help="build the ObjC/Swift feature index (apple lane)")
    ap.add_argument("--find", default=None,
                    help="query the feature index for a keyword (apple lane)")
    ap.add_argument("--limit", type=int, default=40,
                    help="max hits per category for --find")
    ap.add_argument("--sweep", default=None,
                    help="sweep a terms JSON (id+aliases) and print term->hits (any lane)")
    args = ap.parse_args()

    lane = detect_lane(args.target) if args.lane == "auto" else args.lane
    base = os.path.basename(os.path.abspath(args.target).rstrip("/")) or "target"
    out = args.out or os.path.join("coll-out", base)
    bank = EvidenceBank(out)

    if args.sweep:
        from engine import sweep as _sweep
        print(json.dumps(_sweep.sweep(args.target, args.sweep, out, lane), indent=2, ensure_ascii=False))
        return

    # feature-index mode (apple lane)
    if lane == "apple" and (args.index or args.find):
        from engine import apple_v2
        db = os.path.join(bank.root, "objc-index.db")
        if not os.path.exists(db):
            print("# building feature index (first run) ...")
            print("# index:", json.dumps(apple_v2.index_objc(args.target, db), default=str))
        if args.find:
            hits = apple_v2.find(db, args.find, limit=args.limit)
            print(f"# find '{args.find}' — {len(hits)} hits")
            for kind, text in hits:
                print(f"  [{kind}] {text}")
        else:
            print(f"# index -> {db}")
        return

    if lane == "apple":
        report = apple.inspect_apple(args.target, bank)
    elif lane == "web":
        report = web.inspect_web(args.target, bank)
    elif lane == "linux":
        report = linux.inspect_linux(args.target, bank)
    elif lane == "windows":
        report = windows.inspect_windows(args.target, bank)
    elif lane == "unix":
        report = unix.inspect_unix(args.target, bank)
    else:
        report = electron.inspect_electron(args.target, bank)

    manifest = bank.save_manifest()
    print(render(report))
    print(f"\n# evidence -> {os.path.abspath(bank.root)}  (manifest: {manifest})")


if __name__ == "__main__":
    main()
