import tempfile
import unittest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from avagelm.core.provenance import Provenance, Trust
from avagelm.core.tool_runtime import GuardedToolRegistry
from avagelm.demo.task_board import LocalTaskBoard, make_task_registry


class GuardedToolRegistryTests(unittest.TestCase):
    def setUp(self):
        self.calls = []
        self.registry = GuardedToolRegistry()
        self.registry.register(
            "save_note",
            "Save one note",
            {
                "type": "object",
                "properties": {"title": {"type": "string", "minLength": 1, "maxLength": 20}},
                "required": ["title"],
                "additionalProperties": False,
            },
            lambda title: self.calls.append(title) or {"saved": title},
        )
        self.trusted = Provenance("user", Trust.TRUSTED)
        self.untrusted = Provenance("email", Trust.UNTRUSTED)

    def test_trusted_valid_call_runs_handler(self):
        result = self.registry.execute("save_note", {"title": "Read report"}, self.trusted)
        self.assertTrue(result.decision.allowed)
        self.assertEqual(self.calls, ["Read report"])

    def test_untrusted_call_is_blocked_before_handler(self):
        result = self.registry.execute("save_note", {"title": "Read report"}, self.untrusted)
        self.assertFalse(result.decision.allowed)
        self.assertEqual(self.calls, [])

    def test_extra_argument_is_blocked(self):
        result = self.registry.execute(
            "save_note", {"title": "Read report", "admin": True}, self.trusted
        )
        self.assertFalse(result.decision.allowed)
        self.assertEqual(self.calls, [])

    def test_wrong_argument_type_is_blocked(self):
        result = self.registry.execute("save_note", {"title": 4}, self.trusted)
        self.assertFalse(result.decision.allowed)
        self.assertEqual(self.calls, [])

    def test_unknown_tool_is_blocked(self):
        result = self.registry.execute("delete_everything", {}, self.trusted)
        self.assertFalse(result.decision.allowed)
        self.assertEqual(self.calls, [])


class LocalTaskBoardTests(unittest.TestCase):
    def test_task_actions_use_the_guarded_registry_and_local_file(self):
        with tempfile.TemporaryDirectory() as folder:
            board = LocalTaskBoard(Path(folder) / "tasks.json")
            registry = make_task_registry(board)
            trusted = Provenance("user", Trust.TRUSTED)
            added = registry.execute("add_task", {"title": "Prepare slides"}, trusted)
            self.assertTrue(added.decision.allowed)
            self.assertEqual(added.result["id"], 1)
            self.assertEqual(len(board.list_tasks()), 1)

            completed = registry.execute("complete_task", {"task_id": 1}, trusted)
            self.assertTrue(completed.decision.allowed)
            self.assertTrue(completed.result["done"])

            blocked = registry.execute(
                "add_task", {"title": "Injected task"},
                Provenance("outside-note", Trust.UNTRUSTED),
            )
            self.assertFalse(blocked.decision.allowed)
            self.assertEqual(len(board.list_tasks()), 1)


if __name__ == "__main__":
    unittest.main()
