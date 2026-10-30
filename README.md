# agent-delegation-check

Audit a multi-agent delegation graph for unsafe shapes before you deploy it.

When one agent can hand authority to another, the graph drifts: a researcher
that can re-delegate, a child granted a scope its parent never held, a quiet
cycle where two agents can keep passing a task back and forth.
`agent-delegation-check` reads the delegation description itself - not any
runtime traffic - and flags the shapes a reviewer should reject or justify.

Severity is deliberate: **a single loose property is a warning**, because
loose delegation is often intentional. Structural shapes that make authority
unaccountable - cycles, scope amplification, unknown participants - are
errors.

Exit codes: `0` no errors, `1` any error, `2` usage/input problems.

## Requirements

Python 3.10+. Standard library only - no dependencies, no network, no
executor. It never runs the agents it audits.

## Usage

```
python3 delegation_check.py graph.json
python3 delegation_check.py graph.json --json
```

Run the demo and tests:

```
python3 demo.py
python3 -m unittest test_delegation_check
```

## Graph convention

```json
{
  "root": "orchestrator",
  "agents": {
    "orchestrator": {"scopes": ["web.read", "email.send"],
                     "max_depth": 2, "max_children": 3},
    "researcher": {"scopes": ["web.read"]}
  },
  "delegations": [
    {"from": "orchestrator", "to": "researcher",
     "scopes": ["web.read"], "redelegate": false}
  ]
}
```

`scopes` are the authority an agent holds (or an edge grants); `"*"` means
unrestricted. `max_depth` on the root bounds delegation-chain length,
`max_children` bounds fan-out, and `redelegate` on an edge lets the child
pass authority onward (pair it with the edge's `max_depth`). This is a
documented convention for this tool, not an industry standard.

## Rules

| rule | severity | what it catches |
|------|----------|-----------------|
| `invalid-graph` / `invalid-agent` / `invalid-edge` | error | malformed input |
| `unknown-agent` | error | edge or root references an undeclared agent |
| `delegation-cycle` | error | a cycle of delegation edges, including self-loops |
| `scope-amplification` | error | an edge grants a scope the parent does not hold |
| `wildcard-grant` | warning | an edge delegates every scope (`*`) |
| `redelegate-unbounded` | warning | re-delegation allowed with no depth limit |
| `depth-exceeded` | warning | chain deeper than the root's `max_depth` |
| `fanout-exceeded` | warning | node delegates past its `max_children` |
| `unreachable-agent` | info | declared agent not reachable from the root |
| `duplicate-edge` / `unknown-field` | info | housekeeping |

## Limits

- **It audits the description, not behavior.** A clean graph says nothing
  about whether agents honor it at runtime, and a flagged graph may be
  exactly what its owner intended. This is a review signal, not a control.
- **Heuristics, not proof.** Scope coverage is string matching plus `"*"`;
  it does not model scope hierarchies, conditions, or time bounds. A clean
  result does not establish that a graph is safe.
- **Declared limits only.** Depth and fan-out checks apply where the graph
  declares `max_depth` / `max_children`; undeclared means unchecked.
- **Complements, not duplicates, a per-agent permission lint.** Use a
  single-manifest auditor (for example `agent-permission-lint`) for one
  agent's grants; this tool checks how authority moves *between* agents.
- All demo and test data is synthetic.

## License

MIT - see [LICENSE](LICENSE).
