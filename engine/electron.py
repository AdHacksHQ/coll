"""Lane B — Electron / JavaScript bundle feature-surface extraction.

Finds the real app logic (asar or plain JS dir) and extracts the surface a
feature lives on: entry points, module graph, IPC channels, contextBridge
exposures, and routes. Static only — no code is executed.
"""
from __future__ import annotations

import json
import os
import re
from collections import Counter

from .shell import run, slug

_REQUIRE = re.compile(r"""require\(\s*['"]([^'"]+)['"]\s*\)""")
_IMPORT_FROM = re.compile(r"""from\s+['"]([^'"]+)['"]""")
_IMPORT_DYN = re.compile(r"""import\(\s*['"]([^'"]+)['"]\s*\)""")
_IPC_MAIN = re.compile(r"""ipcMain\.(on|handle|once|removeHandler)\(\s*['"]([^'"]+)['"]""")
_IPC_RENDER = re.compile(r"""ipcRenderer\.(invoke|send|sendSync|on|once|removeListener)\(\s*['"]([^'"]+)['"]""")
_EXPOSE = re.compile(r"""contextBridge\.exposeInMainWorld\(\s*['"]([^'"]+)['"]""")
_ROUTE = re.compile(r"""(?:<Route[^>]*path\s*=\s*|path\s*:\s*|route\(\s*)['"]([^'"]+)['"]""")

_JS_EXT = {".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx"}


def _find_asar(app_root: str):
    res = os.path.join(app_root, "Contents", "Resources")
    asar = os.path.join(res, "app.asar")
    return asar if os.path.isfile(asar) else None


def _analyze_js_dir(js_dir: str, bank, target: str, max_files: int = 4000) -> dict:
    files = []
    for dirpath, dirnames, filenames in os.walk(js_dir):
        dirnames[:] = [d for d in dirnames if d not in {"node_modules", ".git"}]
        for fn in filenames:
            if os.path.splitext(fn)[1] in _JS_EXT:
                files.append(os.path.join(dirpath, fn))
    files = files[:max_files]

    requires = Counter()
    ipc_main = set()
    ipc_render = set()
    exposes = set()
    routes = set()
    pkg = None

    for fp in files:
        try:
            if os.path.getsize(fp) > 8_000_000:
                continue
            txt = open(fp, "r", encoding="utf-8", errors="replace").read()
        except OSError:
            continue
        rel = os.path.relpath(fp, js_dir)
        if rel == "package.json":
            try:
                pkg = json.loads(txt)
            except Exception:
                pkg = None
        for m in _REQUIRE.finditer(txt):
            requires[m.group(1)] += 1
        for m in _IMPORT_FROM.finditer(txt):
            requires[m.group(1)] += 1
        for m in _IMPORT_DYN.finditer(txt):
            requires[m.group(1)] += 1
        for m in _IPC_MAIN.finditer(txt):
            ipc_main.add(m.group(2))
        for m in _IPC_RENDER.finditer(txt):
            ipc_render.add(m.group(2))
        for m in _EXPOSE.finditer(txt):
            exposes.add(m.group(1))
        for m in _ROUTE.finditer(txt):
            routes.add(m.group(1))

    top_requires = sorted(requires.items(), key=lambda kv: -kv[1])[:60]
    # keep only external-looking modules (not relative paths)
    ext_requires = [(m, c) for m, c in top_requires if not m.startswith(".")]
    report = {
        "js_files_analyzed": len(files),
        "external_modules": ext_requires,
        "ipc_main_channels": sorted(ipc_main),
        "ipc_renderer_channels": sorted(ipc_render),
        "contextbridge_exposures": sorted(exposes),
        "routes": sorted(routes),
    }
    if pkg:
        report["package"] = {
            "name": pkg.get("name"),
            "version": pkg.get("version"),
            "main": pkg.get("main"),
            "dependencies": list((pkg.get("dependencies") or {}).keys())[:80],
        }
    bank.add("electron", target, "js surface analysis", "coll-regex",
             "static regex over extracted JS", json.dumps(report, indent=2),
             report, confidence="inferred",
             limitation="static text patterns; minified/bundled code may hide channels; no runtime tracing")
    return report


def inspect_electron(target: str, bank) -> dict:
    target = os.path.abspath(target)
    report = {"target": target, "lane": "electron"}

    asar_path = None
    if target.endswith(".app"):
        asar_path = _find_asar(target)
    elif target.endswith(".asar"):
        asar_path = target

    js_dir = None
    if asar_path:
        report["asar"] = asar_path
        rc, listing, _, cmd = run(["asar", "list", asar_path], timeout=60)
        if rc == 0:
            files = [l for l in listing.decode("utf-8", "replace").splitlines() if l.strip()]
            bank.add("electron", target, "asar file inventory", "asar list", cmd, listing,
                     {"file_count": len(files)})
            report["asar_file_count"] = len(files)
        ext = os.path.join(bank.root, "asar-extracted")
        rc, _, err, cmd = run(["asar", "extract", asar_path, ext], timeout=180)
        if rc == 0:
            js_dir = ext
        else:
            report["asar_extract_error"] = err.decode("utf-8", "replace")[:300]
    elif os.path.isdir(target):
        js_dir = target

    if js_dir:
        report["analysis"] = _analyze_js_dir(js_dir, bank, target)
    else:
        report["error"] = "no asar or JS directory found"
    return report
