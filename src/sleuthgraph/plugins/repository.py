"""Case-scoped PluginRun queries for audit UI."""

import uuid

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from sleuthgraph.plugins.models import PluginRun


class PluginRunRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def get(self, run_id: uuid.UUID, case_id: uuid.UUID) -> PluginRun | None:
        q = select(PluginRun).where(
            PluginRun.id == run_id,
            PluginRun.case_id == case_id,
        )
        return (await self.session.execute(q)).scalar_one_or_none()

    async def list_for_case(
        self,
        case_id: uuid.UUID,
        status: str | None = None,
        plugin_name: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[PluginRun], int]:
        filters = [PluginRun.case_id == case_id]
        if status is not None:
            filters.append(PluginRun.status == status)
        if plugin_name is not None:
            filters.append(PluginRun.plugin_name == plugin_name)

        count_q = select(func.count()).select_from(PluginRun).where(*filters)
        total = (await self.session.execute(count_q)).scalar_one()

        items_q = (
            select(PluginRun)
            .where(*filters)
            .order_by(PluginRun.started_at.desc())
            .limit(limit)
            .offset(offset)
        )
        items = list((await self.session.execute(items_q)).scalars())
        return items, total
