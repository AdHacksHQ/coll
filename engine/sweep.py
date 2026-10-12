"""Batch feature sweep — back EVERY canonical term with evidence from one app.

Takes a terms file (Comar's canon/terms.json: [{id, aliases}]) and returns
{term_id: [matched class/member/selector/identifier names]} from a single app,
via the ObjC/Swift index (apple) or a grep over the extracted JS bundle
(electron). This is what turns "61 canonical terms" into "61 backed terms".
"""
from __future__ import annotations

import json
import os
import re
import sqlite3

from . import apple_v2
from .shell import run

_JS_EXT = {".js", ".mjs", ".cjs", ".ts", ".tsx", ".json"}


def _load_terms(path: str) -> list:
    return json.load(open(path))["terms"]


def sweep_index(db_path: str, terms: list, limit: int = 12) -> dict:
    conn = sqlite3.connect(db_path)
    out = {}
    for t in terms:
        kws = [t["id"]] + t.get("aliases", [])
        hits = set()
        for kw in kws:
            kw = kw.lower().strip()
            if not kw or len(kw) < 2:
                continue
            like = f"%{kw}%"
            for tbl, col in (("classes", "demangled"), ("members", "name"), ("selectors", "name")):
                try:
                    for (v,) in conn.execute(
                        f"SELECT {col} FROM {tbl} WHERE {col} LIKE ? LIMIT ?", (like, limit)
                    ):
                        v = str(v)
                        if v and len(v) < 90:
                            hits.add(v)
                except Exception:
                    pass
            if len(hits) >= limit:
                break
        if hits:
            out[t["id"]] = sorted(hits)[:limit]
    conn.close()
    return out


def _extract_js(target: str, out_dir: str) -> str | None:
    ext = os.path.join(out_dir, "asar-extracted")
    if target.endswith(".app"):
        res = os.path.join(target, "Contents", "Resources")
        # 1. unpacked app/ directory (VSCode, Cursor)
        app_dir = os.path.join(res, "app")
        if os.path.isdir(app_dir):
            return app_dir
        # 2. asar(s) — prefer the LARGEST (real app code, not a loader stub)
        asars = [os.path.join(res, f) for f in os.listdir(res)
                 if f.endswith(".asar") and os.path.isfile(os.path.join(res, f))]
        asar = max(asars, key=os.path.getsize) if asars else None
        if asar:
            if not os.path.isdir(ext) or not os.listdir(ext):
                run(["asar", "extract", asar, ext], timeout=300)
            return ext
        return None
    elif target.endswith(".asar"):
        if not os.path.isdir(ext) or not os.listdir(ext):
            run(["asar", "extract", target, ext], timeout=300)
        return ext
    if os.path.isdir(target):
        return target
    return None


def sweep_js(js_dir: str, terms: list, limit: int = 12, max_files: int = 2000, cap: int = 40_000_000) -> dict:
    files = []
    for dp, dn, fn in os.walk(js_dir):
        dn[:] = [d for d in dn if d not in {"node_modules", ".git"}]
        for f in fn:
            if os.path.splitext(f)[1].lower() in _JS_EXT:
                p = os.path.join(dp, f)
                if os.path.getsize(p) < 4_000_000:
                    files.append(p)
    files = files[:max_files]
    blobs, total = [], 0
    for p in files:
        try:
            txt = open(p, encoding="utf-8", errors="replace").read()
        except Exception:
            continue
        if total + len(txt) > cap:
            continue
        blobs.append(txt)
        total += len(txt)
    blob = "\n".join(blobs)
    out = {}
    for t in terms:
        kws = [t["id"]] + t.get("aliases", [])
        hits = set()
        for kw in kws:
            kw = kw.strip()
            if not kw or len(kw) < 2:
                continue
            for m in re.finditer(re.escape(kw), blob, re.IGNORECASE):
                s = max(0, m.start() - 30)
                seg = blob[s:m.end() + 40]
                for tok in re.findall(r"[A-Za-z0-9_\.\-:]+", seg):
                    if kw.lower() in tok.lower() and 2 < len(tok) < 80:
                        hits.add(tok)
                if len(hits) >= limit:
                    break
            if len(hits) >= limit:
                break
        if hits:
            out[t["id"]] = sorted(hits)[:limit]
    return out


def sweep(target: str, terms_path: str, out_dir: str, lane: str) -> dict:
    terms = _load_terms(terms_path)
    os.makedirs(out_dir, exist_ok=True)
    if lane == "apple":
        db = os.path.join(out_dir, "objc-index.db")
        if not os.path.exists(db):
            apple_v2.index_objc(target, db)
        return sweep_index(db, terms)
    js_dir = _extract_js(target, out_dir)
    if not js_dir:
        return {"error": "no asar or JS dir resolved"}
    return sweep_js(js_dir, terms)
