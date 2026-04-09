"""
Authentication module — API Key-based authentication per organisation.

Provides:
- get_org_id(): FastAPI dependency that resolves X-API-Key → org_id (or None for anonymous)
- create_org(): helper to register a new organisation with an API key
"""

import secrets
import logging
from typing import Optional

from fastapi import Security, HTTPException
from fastapi.security import APIKeyHeader
from sqlalchemy import select

from db import AsyncSessionLocal, DB_ENABLED, organizations

logger = logging.getLogger(__name__)

_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


async def get_org_id(
    api_key: Optional[str] = Security(_api_key_header),
) -> Optional[str]:
    """FastAPI dependency — resolves X-API-Key header to an org_id.

    Returns:
        org_id string if a valid key is provided.
        None if no key is provided (anonymous request).

    Raises:
        HTTPException 401 if an invalid key is provided.
        HTTPException 503 if DB is unavailable and a key was provided.
    """
    if not api_key:
        return None  # anonymous request — allowed

    if not DB_ENABLED:
        raise HTTPException(
            status_code=503,
            detail="Database unavailable — API key authentication not possible",
        )

    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(organizations.c.org_id).where(
                organizations.c.api_key == api_key
            )
        )
        row = result.first()

    if row is None:
        raise HTTPException(status_code=401, detail="Invalid API key")

    return row.org_id


def generate_api_key() -> str:
    """Generate a cryptographically secure API key (32-byte hex string)."""
    return secrets.token_hex(32)


async def create_org(org_id: str, name: Optional[str] = None) -> str:
    """Insert a new organisation and return its generated API key.

    Args:
        org_id: Unique identifier for the organisation (e.g. 'acme-corp').
        name:   Human-readable name (optional).

    Returns:
        The generated API key string.

    Raises:
        ValueError if org_id already exists.
        RuntimeError if DB is not available.
    """
    if not DB_ENABLED:
        raise RuntimeError("Database not available")

    api_key = generate_api_key()

    async with AsyncSessionLocal() as session:
        async with session.begin():
            await session.execute(
                organizations.insert().values(
                    org_id=org_id,
                    api_key=api_key,
                    name=name,
                )
            )

    logger.info(f"Organisation created: org_id={org_id}")
    return api_key
