"""Alembic migration environment.

Pulls database URL from Sleuthgraph settings (env-driven) so CI / container
environments don't require an alembic.ini edit.
"""

import asyncio
from logging.config import fileConfig

from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import async_engine_from_config

from alembic import context
from sleuthgraph.config import get_settings
from sleuthgraph.db import Base

# Load models so their metadata is registered on Base.metadata.
from sleuthgraph.auth import models as _auth_models  # noqa: F401
from sleuthgraph.cases import models as _cases_models  # noqa: F401
from sleuthgraph.credentials import models as _cred_models  # noqa: F401
from sleuthgraph.entities import models as _entities_models  # noqa: F401
from sleuthgraph.relationships import models as _rel_models  # noqa: F401
from sleuthgraph.evidence import models as _evidence_models  # noqa: F401
from sleuthgraph.plugins import models as _plugin_models  # noqa: F401

config = context.config
config.set_main_option("sqlalchemy.url", get_settings().database_url)

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def do_run_migrations(connection: Connection) -> None:
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


async def run_migrations_online() -> None:
    connectable = async_engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
    )
    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)
    await connectable.dispose()


def run_migrations_offline() -> None:
    url = config.get_main_option("sqlalchemy.url")
    context.configure(url=url, target_metadata=target_metadata, literal_binds=True)
    with context.begin_transaction():
        context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    asyncio.run(run_migrations_online())
