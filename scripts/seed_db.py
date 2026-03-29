#!/usr/bin/env python3
"""Seed DB with default settings (idempotent)."""
import asyncio
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from shared.db.setup import seed_default_settings


async def main():
    await seed_default_settings()
    print("Settings seeded.")


if __name__ == "__main__":
    asyncio.run(main())
