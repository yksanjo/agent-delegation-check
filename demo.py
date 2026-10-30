#!/usr/bin/env python3
"""Demo: lint a tight delegation graph, then a broken one (all synthetic)."""

import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))

TIGHT = {
    "root": "orchestrator",
    "agents": {
        "orchestrator": {"scopes": ["web.read", "email.read", "email.send"],
                         "max_depth": 2, "max_children": 3},
        "researcher": {"scopes": ["web.read"]},
        "mailer": {"scopes": ["email.read", "email.send"]},
    },
    "delegations": [
        {"from": "orchestrator", "to": "researcher",
         "scopes": ["web.read"], "redelegate": False},
        {"from": "orchestrator", "to": "mailer",
         "scopes": ["email.send"], "redelegate": False},
    ],
}

BROKEN = {
    "root": "orchestrator",
    "agents": {
        "orchestrator": {"scopes": ["web.read", "email.read"], "max_depth": 1},
        "researcher": {"scopes": ["web.read"]},
        "mailer": {"scopes": ["email.read"]},
        "archivist": {"scopes": ["files.read"]},
    },
    "delegations": [
        {"from": "orchestrator", "to": "researcher",
         "scopes": ["web.read"], "redelegate": True},
        {"from": "researcher", "to": "mailer", "scopes": ["*"]},
        {"from": "mailer", "to": "researcher", "scopes": ["web.read"]},
        {"from": "orchestrator", "to": "ghost", "scopes": ["web.read"]},
        {"from": "orchestrator", "to": "researcher",
         "scopes": ["web.read"], "redelegate": True},
    ],
}


def run(name, graph):
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
        json.dump(graph, fh, indent=2)
        path = fh.name
    try:
        print(f"=== {name} ===")
        result = subprocess.run(
            [sys.executable, os.path.join(HERE, "delegation_check.py"), path],
            capture_output=True, text=True)
        print(result.stdout, end="")
        print(f"(exit {result.returncode})\n")
    finally:
        os.unlink(path)


if __name__ == "__main__":
    run("tight graph (scoped, acyclic, within limits)", TIGHT)
    run("broken graph (cycle, amplification, unknown agent, fan-out)", BROKEN)
