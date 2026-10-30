#!/usr/bin/env python3
"""agent-delegation-check: audit a multi-agent delegation graph for unsafe shapes.

Reads a JSON description of agents and their delegation edges and flags the
shapes a reviewer should reject or justify before the graph is deployed:
delegation cycles, scope amplification (an edge granting a child something
the parent does not hold), unbounded re-delegation, and depth/fan-out
violations against declared limits.

Severity is deliberate: a single loose property is a warning, because loose
delegation is often intentional. Structural shapes that make authority
unaccountable - cycles, amplification, unknown participants - are errors.

Exit codes: 0 no errors, 1 any error, 2 usage/input problems.
Standard library only; no network, no executor.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass

KNOWN_AGENT_FIELDS = {"scopes", "max_depth", "max_children"}
KNOWN_EDGE_FIELDS = {"from", "to", "scopes", "redelegate", "max_depth"}


@dataclass
class Finding:
    severity: str  # "error" | "warning" | "info"
    rule: str
    detail: str

    def render(self) -> str:
        return f"[{self.severity:7s}] {self.rule:22s} {self.detail}"


def _wildcard_covers(granted: str, held: list[str]) -> bool:
    """True if `held` covers `granted` ("*" holds everything)."""
    return granted in held or "*" in held


def lint(graph: dict) -> list[Finding]:
    findings: list[Finding] = []

    if not isinstance(graph, dict):
        return [Finding("error", "invalid-graph", "top level must be a JSON object")]

    root = graph.get("root")
    agents = graph.get("agents")
    edges = graph.get("delegations")

    if not isinstance(root, str) or not root:
        findings.append(Finding("error", "invalid-graph",
                                '"root" must name the entry-point agent'))
    if not isinstance(agents, dict) or not agents:
        findings.append(Finding("error", "invalid-graph",
                                '"agents" must be an object of agent definitions'))
        return findings
    if not isinstance(edges, list):
        findings.append(Finding("error", "invalid-graph",
                                '"delegations" must be an array of edges'))
        return findings

    for name, spec in agents.items():
        if not isinstance(spec, dict):
            findings.append(Finding("error", "invalid-agent",
                                    f'agent "{name}" definition must be an object'))
            continue
        unknown = set(spec) - KNOWN_AGENT_FIELDS
        if unknown:
            findings.append(Finding("info", "unknown-field",
                                    f'agent "{name}" has unrecognized fields: '
                                    f'{", ".join(sorted(unknown))}'))
        scopes = spec.get("scopes", [])
        if not isinstance(scopes, list):
            findings.append(Finding("error", "invalid-agent",
                                    f'agent "{name}" scopes must be an array'))

    if root and root not in agents:
        findings.append(Finding("error", "unknown-agent",
                                f'root "{root}" is not declared in agents'))

    # --- validate edges, build adjacency ---------------------------------
    children: dict[str, list[dict]] = {name: [] for name in agents}
    seen_edges: set[tuple] = set()
    valid_edges: list[dict] = []

    for i, edge in enumerate(edges):
        label = f'edge #{i + 1}'
        if not isinstance(edge, dict):
            findings.append(Finding("error", "invalid-edge",
                                    f"{label} must be an object"))
            continue
        frm, to = edge.get("from"), edge.get("to")
        if not isinstance(frm, str) or not isinstance(to, str):
            findings.append(Finding("error", "invalid-edge",
                                    f'{label} needs "from" and "to" agent names'))
            continue
        label = f'edge {frm} -> {to}'
        for endpoint in (frm, to):
            if endpoint not in agents:
                findings.append(Finding("error", "unknown-agent",
                                        f'{label} references undeclared agent '
                                        f'"{endpoint}"'))
        edge_scopes = edge.get("scopes", [])
        if not isinstance(edge_scopes, list):
            findings.append(Finding("error", "invalid-edge",
                                    f"{label} scopes must be an array"))
            continue
        unknown = set(edge) - KNOWN_EDGE_FIELDS
        if unknown:
            findings.append(Finding("info", "unknown-field",
                                    f"{label} has unrecognized fields: "
                                    + ", ".join(sorted(unknown))))
        key = (frm, to, tuple(sorted(edge_scopes)))
        if key in seen_edges:
            findings.append(Finding("info", "duplicate-edge",
                                    f"{label} duplicates an identical delegation"))
        seen_edges.add(key)

        # scope amplification: granting what the parent does not hold
        parent_scopes = agents.get(frm, {}).get("scopes", []) or []
        if frm in agents:
            if "*" in edge_scopes and "*" not in parent_scopes:
                findings.append(Finding("error", "scope-amplification",
                                        f"{label} grants wildcard scope the parent "
                                        f'"{frm}" does not hold'))
            for scope in edge_scopes:
                if scope != "*" and not _wildcard_covers(scope, parent_scopes):
                    findings.append(Finding("error", "scope-amplification",
                                            f'{label} grants "{scope}" which parent '
                                            f'"{frm}" does not hold'))
        if "*" in edge_scopes:
            findings.append(Finding("warning", "wildcard-grant",
                                    f"{label} delegates every scope; a reviewer "
                                    "cannot tell what the child may do"))

        if edge.get("redelegate") and "max_depth" not in edge:
            findings.append(Finding("warning", "redelegate-unbounded",
                                    f"{label} allows re-delegation with no depth "
                                    "limit; authority can propagate past review"))

        valid_edges.append(edge)
        if frm in children:
            children[frm].append(edge)

    # --- cycle detection ---------------------------------------------------
    WHITE, GRAY, BLACK = 0, 1, 2
    color = {name: WHITE for name in agents}
    reported_cycles: set[frozenset] = set()

    def dfs(node: str, stack: list[str]) -> None:
        color[node] = GRAY
        stack.append(node)
        for edge in children.get(node, []):
            nxt = edge["to"]
            if nxt not in color:
                continue
            if color[nxt] == GRAY:
                cyc = stack[stack.index(nxt):] + [nxt]
                key = frozenset(cyc)
                if key not in reported_cycles:
                    reported_cycles.add(key)
                    findings.append(Finding("error", "delegation-cycle",
                                            "delegation cycle: " + " -> ".join(cyc)))
            elif color[nxt] == WHITE:
                dfs(nxt, stack)
        stack.pop()
        color[node] = BLACK

    sys.setrecursionlimit(10000)
    for name in agents:
        if color[name] == WHITE:
            dfs(name, [])

    # --- reachability, depth and fan-out ----------------------------------
    if root in agents:
        depth_of: dict[str, int] = {root: 0}
        queue = [root]
        while queue:
            node = queue.pop(0)
            for edge in children.get(node, []):
                nxt = edge["to"]
                if nxt not in depth_of:
                    depth_of[nxt] = depth_of[node] + 1
                    queue.append(nxt)
        for name in agents:
            if name not in depth_of:
                findings.append(Finding("info", "unreachable-agent",
                                        f'agent "{name}" is not reachable from '
                                        f'root "{root}"'))
        root_max_depth = agents[root].get("max_depth")
        if isinstance(root_max_depth, int):
            for name, depth in depth_of.items():
                if depth > root_max_depth:
                    findings.append(Finding("warning", "depth-exceeded",
                                            f'agent "{name}" sits at depth {depth}, '
                                            f"past the root's max_depth "
                                            f"{root_max_depth}"))

    for name, spec in agents.items():
        max_children = spec.get("max_children") if isinstance(spec, dict) else None
        if isinstance(max_children, int):
            out = len(children.get(name, []))
            if out > max_children:
                findings.append(Finding("warning", "fanout-exceeded",
                                        f'agent "{name}" delegates to {out} agents, '
                                        f"past its max_children {max_children}"))

    order = {"error": 0, "warning": 1, "info": 2}
    findings.sort(key=lambda f: order[f.severity])
    return findings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="agent-delegation-check",
        description="Audit a multi-agent delegation graph for unsafe shapes.")
    parser.add_argument("graph", help="path to the delegation graph JSON file")
    parser.add_argument("--json", action="store_true",
                        help="emit findings as JSON")
    args = parser.parse_args(argv)

    try:
        with open(args.graph, "r", encoding="utf-8") as fh:
            graph = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"agent-delegation-check: cannot read graph: {exc}",
              file=sys.stderr)
        return 2

    findings = lint(graph)
    errors = sum(1 for f in findings if f.severity == "error")
    warnings = sum(1 for f in findings if f.severity == "warning")
    infos = sum(1 for f in findings if f.severity == "info")

    if args.json:
        print(json.dumps({
            "errors": errors,
            "warnings": warnings,
            "infos": infos,
            "ok": errors == 0,
            "findings": [f.__dict__ for f in findings],
        }, indent=2))
    else:
        print(f"agent-delegation-check: {errors} error(s), {warnings} "
              f"warning(s), {infos} info")
        for f in findings:
            print("  " + f.render())
        if not findings:
            print("  no findings: delegation graph is acyclic, scope-safe, "
                  "and within declared limits")
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
