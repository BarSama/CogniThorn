import logging
from contextlib import asynccontextmanager

from sqlalchemy.ext.asyncio import AsyncConnection, create_async_engine

from shared.config.settings import settings
from shared.db.models import metadata

logger = logging.getLogger(__name__)

_engine = None


def get_engine():
    global _engine
    if _engine is None:
        _engine = create_async_engine(
            settings.database_url,
            pool_size=10,
            max_overflow=20,
            pool_pre_ping=True,
            echo=False,
        )
    return _engine


@asynccontextmanager
async def get_conn() -> AsyncConnection:
    async with get_engine().connect() as conn:
        yield conn


async def run_migrations():
    """Create all tables if they don't exist."""
    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(metadata.create_all)
    logger.info("Database migrations complete")
