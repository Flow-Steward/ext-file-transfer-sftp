"""The final extension_host_v2 execution scope every host envelope carries.

All four keys are always present, each a string or null; at most one owner
(Group or For each) is set, and a step always comes with its execution.
"""

from __future__ import annotations

from typing import Any

ROOT_STEP_SCOPE: dict[str, Any] = {
    "group_id": None,
    "for_each_id": None,
    "step_id": "transfer_file",
    "step_execution_id": "8a7b6c5d-4e3f-4a1b-9c8d-7e6f5a4b0001",
}
GROUP_STEP_SCOPE: dict[str, Any] = {**ROOT_STEP_SCOPE, "group_id": "sync_feeds"}
FOR_EACH_STEP_SCOPE: dict[str, Any] = {
    **ROOT_STEP_SCOPE,
    "for_each_id": "each_feed",
    "step_execution_id": "8a7b6c5d-4e3f-4a1b-9c8d-7e6f5a4b0002",
}


def host_context(
    context: dict[str, Any] | None = None, scope: dict[str, Any] | None = None
) -> dict[str, Any]:
    """A runtime context with the execution scope (a For each step by default)."""
    return {**(FOR_EACH_STEP_SCOPE if scope is None else scope), **(context or {})}
