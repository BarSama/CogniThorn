#!/usr/bin/env python3
"""Run database migrations (create tables). Safe to run multiple times."""
import asyncio
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from shared.db.database import run_migrations
from shared.db.setup import seed_default_settings


async def main():
    print("Running migrations...")
    await run_migrations()
    print("Seeding default settings...")
    await seed_default_settings()
    print("Done.")


if __name__ == "__main__":
    asyncio.run(main())
