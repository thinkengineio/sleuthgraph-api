"""arq task stubs.

The full ``run_plugin_task`` implementation lands in Task 6.2; this file is
pre-created so arq_settings.py can import it at worker boot.
"""

from __future__ import annotations

from typing import Any


async def run_plugin_task(ctx: dict[str, Any], run_id: str) -> dict[str, str | int]:  # noqa: ARG001
    """Placeholder — replaced in Task 6.2 with the real runner."""
    raise NotImplementedError("run_plugin_task: implement in Task 6.2")
