#!/usr/bin/env python3
"""Coll MCP server — agents reverse-engineer apps via MCP (stdio JSON-RPC).

Tools: inspect, index, find, sweep
Run: python3 mcp-server.py
Protocol: MCP stdio — JSON-RPC 2.0 over line-delimited messages. No external deps.
"""
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
COLL = os.path.join(HERE, "coll.py")

LANES = ["auto", "apple", "electron", "web", "linux", "windows", "unix"]

TOOLS = [
    {"name": "inspect",
     "description": "Reverse-engineer a target (app/binary/url): Info.plist, entitlements, "
                    "symbols, strings, IPC, routes, SPA surface — evidence-backed.",
     "inputSchema": {"type": "object",
                     "properties": {"target": {"type": "string"},
                                    "lane": {"type": "string", "enum": LANES},
                                    "out": {"type": "string"}},
                     "required": ["target"]}},
    {"name": "index",
     "description": "Build the ObjC/Swift feature index for an app (apple lane).",
     "inputSchema": {"type": "object",
                     "properties": {"target": {"type": "string"}, "out": {"type": "string"}},
                     "required": ["target"]}},
    {"name": "find",
     "description": "Find classes/members/selectors matching a feature keyword in an app's index.",
     "inputSchema": {"type": "object",
                     "properties": {"target": {"type": "string"}, "keyword": {"type": "string"},
                                    "out": {"type": "string"}},
                     "required": ["target", "keyword"]}},
    {"name": "sweep",
     "description": "Sweep a Comar terms.json across a target; returns {term: [hits]}.",
     "inputSchema": {"type": "object",
                     "properties": {"target": {"type": "string"}, "terms": {"type": "string"},
                                    "out": {"type": "string"}},
                     "required": ["target", "terms"]}},
]


def call_tool(name, args):
    cmd = ["python3", COLL]
    if name == "inspect":
        cmd.append(args.get("target", ""))
        if args.get("lane"):
            cmd += ["--lane", args["lane"]]
        if args.get("out"):
            cmd += ["--out", args["out"]]
    elif name == "index":
        cmd += [args.get("target", ""), "--index"]
        if args.get("out"):
            cmd += ["--out", args["out"]]
    elif name == "find":
        cmd += [args.get("target", ""), "--find", args.get("keyword", "")]
        if args.get("out"):
            cmd += ["--out", args["out"]]
    elif name == "sweep":
        cmd += [args.get("target", ""), "--sweep", args.get("terms", "")]
        if args.get("out"):
            cmd += ["--out", args["out"]]
    else:
        return {"isError": True, "content": [{"type": "text", "text": f"unknown tool: {name}"}]}
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    text = (proc.stdout or "") + ((proc.stderr or "") if proc.returncode != 0 else "")
    return {"content": [{"type": "text", "text": text[-8000:]}], "isError": proc.returncode != 0}


def rpc(result_id, result):
    sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": result_id, "result": result}) + "\n")
    sys.stdout.flush()


def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        method = msg.get("method")
        mid = msg.get("id")
        if method == "initialize":
            rpc(mid, {"protocolVersion": "2024-11-05", "capabilities": {"tools": {}},
                      "serverInfo": {"name": "coll", "version": "0.1.0"}})
        elif method == "notifications/initialized" or method is None:
            continue
        elif method == "tools/list":
            rpc(mid, {"tools": TOOLS})
        elif method == "tools/call":
            rpc(mid, call_tool(msg["params"]["name"], msg["params"].get("arguments", {})))
        else:
            if mid is not None:
                sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": mid,
                                             "error": {"code": -32601, "message": f"unknown method {method}"}}) + "\n")
                sys.stdout.flush()


if __name__ == "__main__":
    main()
