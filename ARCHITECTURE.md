# Architecture — Coll absorption manifest

> Doctrine: the default take from an external teardown is a **lesson/approach**,
> not their artifact. Code-take only when the license is clean AND synthesis
> genuinely costs more. Here: license is MIT (clean), but Justin's directive is
> explicit — build it ourselves, better, not dependent on them. So this manifest
> takes the *pattern* and synthesizes our own.

## Source
- `rea-agents` (MIT, ~135k stars), April 2026 → "Reverse Engineer Anything."
  Started as a Hopper-disassembler MCP wrapper, grew into a general
  reverse-engineering MCP + investigation workflow for Claude Code/Codex/Cursor.

## What we take (pattern, not code)
1. **One agent interface over a catalog of per-target backends** — an agent
   asks "inspect this," the tool routes by target type, returns findings the
   agent can follow up on.
2. **Evidence discipline** — every finding ships with its reproduction input +
   explicit limitations; "concise findings + reproduction inputs"; no fake
   conclusions. This is the single highest-value idea in REA and it maps
   one-to-one onto our own verify-never-report kernel law.
3. **Investigation model** — inspect → trace → follow-up question → rebuild.
4. **Ownership/provenance** — produced artifacts are attributed, never claimed
   as established fact without evidence.

## What we build ourselves (surpass thesis)
| REA's way | Coll's way |
|-----------|----------------|
| Hopper/Ghidra/IDA seats (paid / heavy) | installed free Apple toolchain + `lldb` |
| Node/TS tree: Playwright, WABT, JADX, apktool, Binwalk, pwntools | Python 3 stdlib orchestrator |
| Claude Code-first npm package | estate-native CLI + (next) MCP + skill, callable by our roster |
| kitchen-sink catalog of 20 target types | the lanes Justin actually uses, done deep |
| macOS parser bolted on late | Apple/macOS-native from day one (our estate is a Mac Studio) |

## Evidence contract
```
Finding: {lane, target, label, tool, command, summary, artifact, digest, confidence, limitation}
```
- `command` is the exact shlex-quoted argv → reproducible by hand.
- `digest` is blake2b-128 of the raw artifact → re-verifiable byte-for-byte.
- `confidence` ∈ observed | inferred | unknown → the finding never overclaims.
- `limitation` is mandatory on inferred findings → e.g. "strings is heuristic".

## Lane status
- ✅ **apple** — `.app`/Mach-O: Info.plist facts, entitlements, signature,
  binary inventory (arch, linked libs), ObjC class/protocol/category surface,
  demangled Swift symbol surface, strings signal (selectors/URLs/flags).
  Verified end-to-end on Telegram.app (31 binaries, 291 ObjC classes, 1,930
  Swift symbols, 4,382 selectors, live feature flags).
- ✅ **electron** — `.asar`/JS: package facts, external-module histogram, IPC
  main/renderer channels, contextBridge exposures, routes. Verified on
  Notion.app (13 exposures incl. `__electronApi`, `__mediaApi`,
  `__sqliteBrowserApi`, `tabsApi`).

## Roadmap (unbuilt, in priority order)
1. **Lane A v2 — full ObjC method dump** via `objdump --macho --objc-meta-data`
   (Telegram yields 517k lines: classes + methods + protocols), parsed to a
   queryable class/method index. This is the "find the exact method behind a
   feature" upgrade.
2. **`trace` lane** — `lldb`-driven runtime tracing: attach to a running app,
   set breakpoints/watchpoints, capture call stacks + args while a feature runs.
   Turns "what's in the binary" into "what actually happens."
3. **MCP + skill wiring** — expose as an MCP server + a discoverable skill so
   the roster invokes it the same way it invokes the Consumer (`source.py app:`).
4. **`web` lane** — delegate website feature capture to the existing
   `browser_exec` tool, reuse the same evidence contract.
5. **Other platforms on demand** — ELF/Linux, PE/Windows, APK — only when a real
   job demands one; contracts are already platform-agnostic.

## Open decisions (Justin)
- **Name** — "Coll" is a working title. Run through the estate naming
  protocol or name it outright.
- **Home** — currently `viiy-hq/tools/coll` (untracked). Promote to its own
  repo, or fold under an existing one.
- **Next lane** — ratify the roadmap order above, or point at a real feature
  you want pulled out of a specific app as the first production job.
