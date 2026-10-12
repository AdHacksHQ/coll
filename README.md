# Coll — reverse-engineer a feature from an app, our way

Reverse-engineer the *surface* of any macOS app — native `.app`/Mach-O or
Electron/JS bundle — into evidence-backed findings an agent can act on. Built
for the one job Justin keeps hitting: *"I like feature X in app Y — build it
for me."* This is how Viiy actually looks inside app Y.

**Not a dependency on REA.** We took REA's *pattern* (agent interface +
evidence discipline + per-target backends) and synthesized our own:

- **Apple-native, license-free.** Uses the installed free toolchain (`otool`,
  `nm`, `objdump`, `lipo`, `file`, `plutil`, `codesign`, `strings`, `lldb`,
  `xcrun swift-demangle`) — no Hopper/Ghidra/IDA seat needed.
- **Stdlib-only orchestrator.** Python 3 stdlib, no heavy Node/TS tree. Mirrors
  the Consumer's law.
- **Evidence, not vibes.** Every finding carries the exact command, a
  byte-pinned digest, and an explicit confidence + limitation.

## Quick start

```
python3 coll.py /Applications/Notion.app          # auto -> electron
python3 coll.py /Applications/Telegram.app --lane apple
python3 coll.py <any>.asar --lane electron
```

Concise findings print to stdout; the full evidence + `manifest.json` land in
`--out` (default `coll-out/<name>`).

## Lanes

| Lane | Target | Status |
|------|--------|--------|
| `apple` | `.app` / Mach-O — Info.plist, entitlements, signature, binaries, linked libs, ObjC/Swift symbol surface, strings signal | ✅ working |
| `electron` | `.asar` / JS bundle — package, module graph, IPC channels, contextBridge exposures, routes | ✅ working |
| `apple` v2 | full ObjC class/method dump via `objdump --macho --objc-meta-data` | roadmap |
| `trace` | runtime feature tracing via `lldb` (see a feature *run*, not just its symbols) | roadmap |
| `web` | website feature capture (delegates to existing `browser_exec`) | roadmap |

## Laws

- **Static only.** Nothing from the target is executed.
- **No DRM breaking.** Inspect behavior, not license bypass.
- **Evidence-backed.** No conclusion without its artifact + reproduction command.
- **Platform-agnostic contracts** (estate law): the report schema is stable;
  per-platform backends slot in (Mach-O/Apple, ELF/Linux, PE/Windows) and fail
  closed when a tool is missing.

## Layout

```
coll.py          CLI front door (lane detect + render)
engine/shell.py      safe subprocess (argv-only, quoted repro)
engine/evidence.py   Finding + EvidenceBank (digest, manifest)
engine/apple.py      Lane A — .app / Mach-O
engine/electron.py   Lane B — Electron / JS bundle
```
