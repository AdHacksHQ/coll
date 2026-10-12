"""Lane A v2 — full ObjC/Swift class + member index, feature-findable.

Turns a Mach-O binary into a queryable SQLite index so an agent can answer
"which class/method implements feature X" instead of grepping raw dumps.

Sources (all free, installed):
  - objdump --macho --objc-meta-data  (class list, superclasses)
  - otool -ov                         (class -> method/ivar/property mapping)
  - nm -gj                            (symbols, protocols, categories)
  - strings                           (selector + URL + flag signal)
  - xcrun swift-demangle              (Swift type names)
"""
from __future__ import annotations

import os
import plistlib
import re
import sqlite3
from collections import Counter

from .shell import run, slug

_NAME = re.compile(r"^\s*name\s+(0x[0-9a-fA-F]+)\s+(.+?)\s*$")
_SUPER = re.compile(r"^\s*superclass\s+0x[0-9a-fA-F]+\s+(.+?)\s*$")
_OBJC_CLASS = re.compile(r"^_OBJC_CLASS_\$_(.+)$")
_OBJC_PROTO = re.compile(r"^_OBJC_PROTOCOL_\$_(.+)$")
_OBJC_CAT = re.compile(r"^_OBJC_\$_CATEGORY_(.+)_\$_(.+)$")
_SWIFT_SYM = re.compile(r"^_\$[sS]")
_SWIFT_CLS = re.compile(r"^_TtC|^_\$[sS]")   # legacy _TtC + modern _$s mangling
_SELECTOR = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]*(?::[a-zA-Z0-9_]+)*:$")


def _resolve_binary(target: str):
    target = os.path.abspath(target)
    if target.endswith(".app") or os.path.exists(os.path.join(target, "Contents")):
        exe = None
        pl = os.path.join(target, "Contents", "Info.plist")
        if os.path.exists(pl):
            with open(pl, "rb") as f:
                exe = plistlib.load(f).get("CFBundleExecutable")
        cand = os.path.join(target, "Contents", "MacOS", exe) if exe else None
        if cand and os.path.isfile(cand):
            return cand
        m = os.path.join(target, "Contents", "MacOS")
        if os.path.isdir(m):
            for f in os.listdir(m):
                if os.path.isfile(os.path.join(m, f)):
                    return os.path.join(m, f)
        return None
    return target if os.path.isfile(target) else None


def _demangle_swift(names: list[str]) -> dict[str, str]:
    """Demangle a batch of Swift names via xcrun; returns {mangled: demangled}."""
    out = {}
    swift = [n for n in names if _SWIFT_CLS.match(n)]
    if not swift:
        return out
    joined = ("\n".join(swift) + "\n").encode()
    rc, res, _, _ = run(["xcrun", "swift-demangle", "--compact"], timeout=120, input_bytes=joined)
    if rc != 0:
        return out
    lines = res.decode("utf-8", "replace").splitlines()
    for m, d in zip(swift, lines):
        d = d.strip()
        out[m] = d if d and d != m else m
    return out


def _parse_otool(text: str):
    """Parse `otool -ov` into {class_name: {members}, ...} + superclass map."""
    classes: dict[str, set] = {}
    supers: dict[str, str] = {}
    current = None
    pending_super = None
    expect_class = False
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("data ") and ("class_ro_t" in s or "Swift class" in s or "class_t" in s):
            expect_class = True
            continue
        m = _SUPER.match(line)
        if m:
            pending_super = m.group(1).strip()
            continue
        m = _NAME.match(line)
        if m:
            val = m.group(2).strip()
            if expect_class:
                current = val
                classes.setdefault(val, set())
                if pending_super:
                    supers[val] = pending_super
                    pending_super = None
                expect_class = False
            elif current is not None:
                classes[current].add(val)
    return classes, supers


def index_objc(target: str, db_path: str) -> dict:
    binary = _resolve_binary(target)
    if not binary:
        return {"error": f"no Mach-O binary resolved from {target}"}
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.executescript("""
        CREATE TABLE IF NOT EXISTS classes(name TEXT, demangled TEXT, superclass TEXT, kind TEXT);
        CREATE TABLE IF NOT EXISTS members(class TEXT, name TEXT);
        CREATE TABLE IF NOT EXISTS selectors(name TEXT);
        CREATE INDEX IF NOT EXISTS idx_classes ON classes(demangled);
        CREATE INDEX IF NOT EXISTS idx_members ON members(name);
    """)
    c.execute("DELETE FROM classes"); c.execute("DELETE FROM members"); c.execute("DELETE FROM selectors")

    # 1. otool -ov -> class -> member mapping
    rc, out, _, cmd = run(["otool", "-ov", binary], timeout=240)
    otool_classes, supers = {}, {}
    if rc == 0:
        otool_classes, supers = _parse_otool(out.decode("utf-8", "replace"))

    # 2. demangle class names
    all_cls = list(otool_classes.keys())
    dem = _demangle_swift(all_cls)

    # 3. nm -gj -> protocols, categories, swift symbol count (for full surface)
    rc, nout, _, cmd = run(["nm", "-gj", binary], timeout=180)
    protos, cats = set(), set()
    if rc == 0:
        for line in nout.decode("utf-8", "replace").splitlines():
            line = line.strip()
            m = _OBJC_PROTO.match(line)
            if m:
                protos.add(m.group(1)); continue
            m = _OBJC_CAT.match(line)
            if m:
                cats.add(f"{m.group(1)} ({m.group(2)})")

    # 4. strings -> selectors
    rc, sout, _, cmd = run(["strings", "-", binary], timeout=180)
    selectors = set()
    if rc == 0:
        for line in sout.decode("utf-8", "replace").splitlines():
            s = line.strip()
            if 2 <= len(s) <= 160 and _SELECTOR.match(s):
                selectors.add(s)

    # insert
    for mangled, members in otool_classes.items():
        m = _OBJC_CLASS.match(mangled)
        d = m.group(1) if m else dem.get(mangled, mangled)
        sup = supers.get(mangled, "")
        ms = _OBJC_CLASS.match(sup or "")
        if ms:
            sup = ms.group(1)
        c.execute("INSERT INTO classes VALUES (?,?,?,?)", (mangled, d, sup, "class"))
        for mem in members:
            c.execute("INSERT INTO members VALUES (?,?)", (d, mem))
    for p in protos:
        c.execute("INSERT INTO classes VALUES (?,?,?,?)", (p, p, "", "protocol"))
    for s in selectors:
        c.execute("INSERT INTO selectors VALUES (?)", (s,))

    conn.commit()
    stats = {
        "binary": binary,
        "db": db_path,
        "classes": len(otool_classes),
        "protocols": len(protos),
        "categories": len(cats),
        "members": c.execute("SELECT COUNT(*) FROM members").fetchone()[0],
        "selectors": len(selectors),
    }
    conn.close()
    return stats


def find(db_path: str, keyword: str, limit: int = 40) -> list[tuple[str, str]]:
    kw = f"%{keyword}%"
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    out = []
    for kind, sql in [
        ("class", "SELECT demangled FROM classes WHERE demangled LIKE ? LIMIT ?"),
        ("member", "SELECT class || '  →  ' || name FROM members WHERE name LIKE ? LIMIT ?"),
        ("selector", "SELECT name FROM selectors WHERE name LIKE ? LIMIT ?"),
    ]:
        c.execute(sql, (kw, limit))
        for row in c.fetchall():
            out.append((kind, row[0]))
    conn.close()
    return out
