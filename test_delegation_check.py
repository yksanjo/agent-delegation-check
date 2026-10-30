import json
import os
import subprocess
import sys
import tempfile
import unittest

from delegation_check import lint

HERE = os.path.dirname(os.path.abspath(__file__))


def tight_graph():
    return {
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


class TestValidGraph(unittest.TestCase):
    def test_tight_graph_has_no_findings(self):
        self.assertEqual(lint(tight_graph()), [])

    def test_top_level_not_object(self):
        findings = lint([1, 2, 3])
        self.assertEqual(findings[0].rule, "invalid-graph")
        self.assertEqual(findings[0].severity, "error")

    def test_missing_agents_block(self):
        findings = lint({"root": "a", "delegations": []})
        self.assertTrue(any(f.rule == "invalid-graph" for f in findings))

    def test_missing_delegations_block(self):
        findings = lint({"root": "a", "agents": {"a": {"scopes": []}}})
        self.assertTrue(any(f.rule == "invalid-graph" for f in findings))

    def test_root_not_declared(self):
        g = tight_graph()
        g["root"] = "ghost"
        rules = {f.rule for f in lint(g)}
        self.assertIn("unknown-agent", rules)


class TestEdges(unittest.TestCase):
    def test_unknown_endpoint(self):
        g = tight_graph()
        g["delegations"].append({"from": "orchestrator", "to": "ghost",
                                 "scopes": []})
        findings = lint(g)
        self.assertTrue(any(f.rule == "unknown-agent" and "ghost" in f.detail
                            for f in findings))

    def test_scope_amplification(self):
        g = tight_graph()
        g["delegations"].append({"from": "researcher", "to": "mailer",
                                 "scopes": ["vault.read"]})
        findings = lint(g)
        self.assertTrue(any(f.rule == "scope-amplification"
                            and "vault.read" in f.detail
                            and f.severity == "error" for f in findings))

    def test_wildcard_child_of_scoped_parent_is_amplification(self):
        g = tight_graph()
        g["delegations"].append({"from": "researcher", "to": "mailer",
                                 "scopes": ["*"]})
        findings = lint(g)
        self.assertTrue(any(f.rule == "scope-amplification"
                            and f.severity == "error" for f in findings))

    def test_wildcard_grant_warns_even_when_parent_holds_wildcard(self):
        g = tight_graph()
        g["agents"]["orchestrator"]["scopes"] = ["*"]
        g["delegations"].append({"from": "orchestrator", "to": "researcher",
                                 "scopes": ["*"]})
        findings = lint(g)
        self.assertTrue(any(f.rule == "wildcard-grant"
                            and f.severity == "warning" for f in findings))
        self.assertFalse(any(f.rule == "scope-amplification"
                             for f in findings))

    def test_parent_wildcard_covers_child_scope(self):
        g = tight_graph()
        g["agents"]["researcher"]["scopes"] = ["*"]
        g["delegations"].append({"from": "researcher", "to": "mailer",
                                 "scopes": ["vault.read"]})
        self.assertFalse(any(f.rule == "scope-amplification"
                             for f in lint(g)))

    def test_redelegate_without_depth_limit_warns(self):
        g = tight_graph()
        g["delegations"][0]["redelegate"] = True
        findings = lint(g)
        self.assertTrue(any(f.rule == "redelegate-unbounded"
                            and f.severity == "warning" for f in findings))

    def test_redelegate_with_depth_limit_does_not_warn(self):
        g = tight_graph()
        g["delegations"][0]["redelegate"] = True
        g["delegations"][0]["max_depth"] = 1
        self.assertFalse(any(f.rule == "redelegate-unbounded"
                             for f in lint(g)))

    def test_duplicate_edge_is_info(self):
        g = tight_graph()
        g["delegations"].append(dict(g["delegations"][0]))
        findings = lint(g)
        self.assertTrue(any(f.rule == "duplicate-edge"
                            and f.severity == "info" for f in findings))

    def test_edge_scopes_not_array(self):
        g = tight_graph()
        g["delegations"].append({"from": "orchestrator", "to": "mailer",
                                 "scopes": "email.send"})
        self.assertTrue(any(f.rule == "invalid-edge" for f in lint(g)))


class TestStructure(unittest.TestCase):
    def test_two_node_cycle_is_error(self):
        g = tight_graph()
        g["agents"]["researcher"]["scopes"].append("web.read")
        g["delegations"].append({"from": "researcher", "to": "orchestrator",
                                 "scopes": ["web.read"]})
        findings = lint(g)
        self.assertTrue(any(f.rule == "delegation-cycle"
                            and f.severity == "error" for f in findings))

    def test_self_loop_is_cycle(self):
        g = tight_graph()
        g["delegations"].append({"from": "mailer", "to": "mailer",
                                 "scopes": ["email.send"]})
        self.assertTrue(any(f.rule == "delegation-cycle" for f in lint(g)))

    def test_unreachable_agent_is_info(self):
        g = tight_graph()
        g["agents"]["archivist"] = {"scopes": ["files.read"]}
        findings = lint(g)
        self.assertTrue(any(f.rule == "unreachable-agent"
                            and "archivist" in f.detail
                            and f.severity == "info" for f in findings))

    def test_depth_exceeded_warns(self):
        g = tight_graph()
        g["agents"]["orchestrator"]["max_depth"] = 1
        g["agents"]["helper"] = {"scopes": ["web.read"]}
        g["delegations"].append({"from": "researcher", "to": "helper",
                                 "scopes": ["web.read"]})
        findings = lint(g)
        self.assertTrue(any(f.rule == "depth-exceeded" and "helper" in f.detail
                            and f.severity == "warning" for f in findings))

    def test_fanout_exceeded_warns(self):
        g = tight_graph()
        g["agents"]["orchestrator"]["max_children"] = 1
        findings = lint(g)
        self.assertTrue(any(f.rule == "fanout-exceeded"
                            and f.severity == "warning" for f in findings))

    def test_unknown_fields_are_info(self):
        g = tight_graph()
        g["agents"]["mailer"]["owner"] = "ops"
        g["delegations"][0]["note"] = "temp"
        findings = lint(g)
        infos = [f for f in findings if f.rule == "unknown-field"]
        self.assertEqual(len(infos), 2)


class TestCli(unittest.TestCase):
    def run_cli(self, graph):
        with tempfile.NamedTemporaryFile("w", suffix=".json",
                                         delete=False) as fh:
            json.dump(graph, fh)
            path = fh.name
        try:
            return subprocess.run(
                [sys.executable, os.path.join(HERE, "delegation_check.py"),
                 path, "--json"],
                capture_output=True, text=True)
        finally:
            os.unlink(path)

    def test_clean_graph_exit_zero(self):
        result = self.run_cli(tight_graph())
        self.assertEqual(result.returncode, 0)
        self.assertTrue(json.loads(result.stdout)["ok"])

    def test_error_graph_exit_one(self):
        g = tight_graph()
        g["delegations"].append({"from": "researcher", "to": "orchestrator",
                                 "scopes": ["web.read"]})
        result = self.run_cli(g)
        self.assertEqual(result.returncode, 1)
        self.assertFalse(json.loads(result.stdout)["ok"])

    def test_bad_file_exit_two(self):
        result = subprocess.run(
            [sys.executable, os.path.join(HERE, "delegation_check.py"),
             "/nonexistent/graph.json"],
            capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)


if __name__ == "__main__":
    unittest.main()
