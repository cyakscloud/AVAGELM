"""A tiny local task list for trying the guardrail on familiar actions."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from avagelm.core.tool_runtime import GuardedToolRegistry


class LocalTaskBoard:
    """Store demo tasks in one JSON file inside the project artifacts folder."""

    def __init__(self, path: Path) -> None:
        self.path = path

    def _read(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ValueError("The local task file is not valid JSON") from exc
        if not isinstance(data, list) or any(not isinstance(row, dict) for row in data):
            raise ValueError("The local task file has an unexpected format")
        return data

    def _write(self, tasks: list[dict[str, Any]]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_suffix(self.path.suffix + ".tmp")
        temporary.write_text(json.dumps(tasks, indent=2), encoding="utf-8")
        temporary.replace(self.path)

    def list_tasks(self) -> list[dict[str, Any]]:
        return self._read()

    def add_task(self, title: str) -> dict[str, Any]:
        title = title.strip()
        if not title or len(title) > 120:
            raise ValueError("Task title must contain 1 to 120 characters")
        tasks = self._read()
        task_id = max((int(task.get("id", 0)) for task in tasks), default=0) + 1
        task = {"id": task_id, "title": title, "done": False}
        tasks.append(task)
        self._write(tasks)
        return task

    def complete_task(self, task_id: int) -> dict[str, Any]:
        tasks = self._read()
        for task in tasks:
            if task.get("id") == task_id:
                task["done"] = True
                self._write(tasks)
                return task
        raise ValueError(f"Task {task_id} was not found")


def make_task_registry(board: LocalTaskBoard) -> GuardedToolRegistry:
    registry = GuardedToolRegistry()
    registry.register(
        "list_tasks",
        "Show the tasks in the local demo task list.",
        {"type": "object", "properties": {}, "required": [], "additionalProperties": False},
        board.list_tasks,
    )
    registry.register(
        "add_task",
        "Add one task to the local demo task list.",
        {"type": "object", "properties": {
            "title": {"type": "string", "minLength": 1, "maxLength": 120},
        }, "required": ["title"], "additionalProperties": False},
        board.add_task,
    )
    registry.register(
        "complete_task",
        "Mark a task complete using its numeric task ID.",
        {"type": "object", "properties": {
            "task_id": {"type": "integer", "minimum": 1},
        }, "required": ["task_id"], "additionalProperties": False},
        board.complete_task,
    )
    return registry
