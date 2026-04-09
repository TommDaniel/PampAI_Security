"""
Database module — PostgreSQL connection and schema definitions.

Provides:
- Async SQLAlchemy engine / session factory
- Table metadata (organisations, phishing_events, alert_configs)
- init_db() to create tables on first run
"""

import os
import logging
from typing import Optional

from sqlalchemy import (
    BigInteger,
    Boolean,
    Column,
    Date,
    Float,
    MetaData,
    String,
    Table,
    Text,
    TIMESTAMP,
    Integer,
    cast,
    func,
    case,
    select,
)
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Connection
# ---------------------------------------------------------------------------

DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql+asyncpg://phishing:phishing@localhost:5432/phishing",
)

engine = create_async_engine(DATABASE_URL, echo=False, pool_pre_ping=True)

AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
)

metadata = MetaData()

# ---------------------------------------------------------------------------
# Tables
# ---------------------------------------------------------------------------

organizations = Table(
    "organizations",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("org_id", String(64), unique=True, nullable=False),
    Column("api_key", String(128), unique=True, nullable=False),
    Column("name", String(255), nullable=True),
    Column(
        "created_at",
        TIMESTAMP(timezone=True),
        server_default=func.now(),
        nullable=False,
    ),
)

phishing_events = Table(
    "phishing_events",
    metadata,
    Column("id", BigInteger, primary_key=True, autoincrement=True),
    Column("org_id", String(64), nullable=True),       # NULL for anonymous requests
    Column("event_type", String(16), nullable=False),  # 'url' | 'email'
    # URL-specific
    Column("url", Text, nullable=True),
    # Email-specific
    Column("email_subject", Text, nullable=True),
    Column("email_sender", Text, nullable=True),
    # Detection result
    Column("is_phishing", Boolean, nullable=False),
    Column("confidence", Float, nullable=False),
    Column("label", String(16), nullable=False),       # PHISHING | LEGITIMO | SUSPICIOUS
    Column("analysis", Text, nullable=True),
    Column("inference_ms", Float, nullable=True),
    Column("source", String(16), nullable=True),       # bert | cascade | catboost
    # Email score & translation metadata
    Column("email_score", Float, nullable=True),
    Column("language_detected", String(16), nullable=True),
    Column("translated", Boolean, nullable=True, default=False),
    # Extension metadata
    Column("extension_id", String(128), nullable=True),
    Column("user_agent", Text, nullable=True),
    Column(
        "created_at",
        TIMESTAMP(timezone=True),
        server_default=func.now(),
        nullable=False,
    ),
)

alert_configs = Table(
    "alert_configs",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("org_id", String(64), nullable=False),
    Column("alert_type", String(16), nullable=False),  # 'webhook' | 'email'
    Column("endpoint", Text, nullable=False),          # webhook URL or email address
    Column("enabled", Boolean, nullable=False, default=True),
    Column(
        "created_at",
        TIMESTAMP(timezone=True),
        server_default=func.now(),
        nullable=False,
    ),
    Column(
        "updated_at",
        TIMESTAMP(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    ),
)

# ---------------------------------------------------------------------------
# Initialisation
# ---------------------------------------------------------------------------

DB_ENABLED = False  # Set to True after successful init_db()


async def init_db() -> None:
    """Create all tables if they do not exist yet."""
    global DB_ENABLED
    try:
        async with engine.begin() as conn:
            await conn.run_sync(metadata.create_all)
        DB_ENABLED = True
        logger.info("PostgreSQL conectado e schema criado/verificado.")
    except Exception as exc:
        logger.warning(
            f"PostgreSQL indisponivel — persistencia desativada. Erro: {exc}"
        )
        DB_ENABLED = False


async def close_db() -> None:
    """Dispose the async engine connection pool."""
    await engine.dispose()
    logger.info("Pool de conexoes PostgreSQL encerrado.")


async def log_event(
    *,
    org_id: Optional[str],
    event_type: str,
    is_phishing: bool,
    confidence: float,
    label: str,
    url: Optional[str] = None,
    email_subject: Optional[str] = None,
    email_sender: Optional[str] = None,
    analysis: Optional[str] = None,
    inference_ms: "Optional[float]" = None,
    source: Optional[str] = None,
    email_score: "Optional[float]" = None,
    language_detected: Optional[str] = None,
    translated: "Optional[bool]" = None,
    extension_id: Optional[str] = None,
    user_agent: Optional[str] = None,
) -> dict:
    """Insert a phishing event and return the persisted row as a dict.

    Raises RuntimeError if DB is not available.
    """
    from typing import Optional as _Opt  # noqa: F401 — used only for type hints above

    if not DB_ENABLED:
        raise RuntimeError("Database not available")

    values = dict(
        org_id=org_id,
        event_type=event_type,
        is_phishing=is_phishing,
        confidence=confidence,
        label=label,
        url=url,
        email_subject=email_subject,
        email_sender=email_sender,
        analysis=analysis,
        inference_ms=inference_ms,
        source=source,
        email_score=email_score,
        language_detected=language_detected,
        translated=translated,
        extension_id=extension_id,
        user_agent=user_agent,
    )

    async with AsyncSessionLocal() as session:
        async with session.begin():
            result = await session.execute(
                phishing_events.insert().values(**values).returning(
                    phishing_events.c.id,
                    phishing_events.c.created_at,
                )
            )
            row = result.first()

    return {**values, "id": row.id, "created_at": row.created_at}


async def get_alert_configs(org_id: str, alert_type: str) -> list[dict]:
    """Return enabled alert configs for an org and type ('webhook' or 'email').

    Returns an empty list if DB is not available or no configs found.
    """
    if not DB_ENABLED:
        return []

    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(
                alert_configs.c.id,
                alert_configs.c.org_id,
                alert_configs.c.alert_type,
                alert_configs.c.endpoint,
                alert_configs.c.enabled,
            ).where(
                alert_configs.c.org_id == org_id,
                alert_configs.c.alert_type == alert_type,
                alert_configs.c.enabled == True,  # noqa: E712
            )
        )
        rows = result.fetchall()

    return [
        {
            "id": row.id,
            "org_id": row.org_id,
            "alert_type": row.alert_type,
            "endpoint": row.endpoint,
            "enabled": row.enabled,
        }
        for row in rows
    ]


async def list_alert_configs(org_id: str) -> list[dict]:
    """Return all alert configs for an org (both enabled and disabled).

    Raises RuntimeError if DB is not available.
    """
    if not DB_ENABLED:
        raise RuntimeError("Database not available")

    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(
                alert_configs.c.id,
                alert_configs.c.org_id,
                alert_configs.c.alert_type,
                alert_configs.c.endpoint,
                alert_configs.c.enabled,
                alert_configs.c.created_at,
                alert_configs.c.updated_at,
            ).where(alert_configs.c.org_id == org_id)
            .order_by(alert_configs.c.id)
        )
        rows = result.fetchall()

    return [
        {
            "id": row.id,
            "org_id": row.org_id,
            "alert_type": row.alert_type,
            "endpoint": row.endpoint,
            "enabled": row.enabled,
            "created_at": row.created_at,
            "updated_at": row.updated_at,
        }
        for row in rows
    ]


async def create_alert_config(
    org_id: str,
    alert_type: str,
    endpoint: str,
    enabled: bool = True,
) -> dict:
    """Insert a new alert config and return the persisted row as a dict.

    Raises RuntimeError if DB is not available.
    """
    if not DB_ENABLED:
        raise RuntimeError("Database not available")

    values = dict(org_id=org_id, alert_type=alert_type, endpoint=endpoint, enabled=enabled)

    async with AsyncSessionLocal() as session:
        async with session.begin():
            result = await session.execute(
                alert_configs.insert().values(**values).returning(
                    alert_configs.c.id,
                    alert_configs.c.created_at,
                    alert_configs.c.updated_at,
                )
            )
            row = result.first()

    return {**values, "id": row.id, "created_at": row.created_at, "updated_at": row.updated_at}


async def update_alert_config(
    config_id: int,
    org_id: str,
    endpoint: Optional[str] = None,
    enabled: Optional[bool] = None,
) -> Optional[dict]:
    """Update an alert config by id (scoped to org_id for safety).

    Returns the updated row dict, or None if not found.
    Raises RuntimeError if DB is not available.
    """
    if not DB_ENABLED:
        raise RuntimeError("Database not available")

    updates: dict = {}
    if endpoint is not None:
        updates["endpoint"] = endpoint
    if enabled is not None:
        updates["enabled"] = enabled

    if not updates:
        # Nothing to update — fetch and return current row
        async with AsyncSessionLocal() as session:
            result = await session.execute(
                select(alert_configs).where(
                    alert_configs.c.id == config_id,
                    alert_configs.c.org_id == org_id,
                )
            )
            row = result.first()
        if row is None:
            return None
        return {
            "id": row.id,
            "org_id": row.org_id,
            "alert_type": row.alert_type,
            "endpoint": row.endpoint,
            "enabled": row.enabled,
            "created_at": row.created_at,
            "updated_at": row.updated_at,
        }

    async with AsyncSessionLocal() as session:
        async with session.begin():
            result = await session.execute(
                alert_configs.update()
                .where(
                    alert_configs.c.id == config_id,
                    alert_configs.c.org_id == org_id,
                )
                .values(**updates)
                .returning(
                    alert_configs.c.id,
                    alert_configs.c.org_id,
                    alert_configs.c.alert_type,
                    alert_configs.c.endpoint,
                    alert_configs.c.enabled,
                    alert_configs.c.created_at,
                    alert_configs.c.updated_at,
                )
            )
            row = result.first()

    if row is None:
        return None

    return {
        "id": row.id,
        "org_id": row.org_id,
        "alert_type": row.alert_type,
        "endpoint": row.endpoint,
        "enabled": row.enabled,
        "created_at": row.created_at,
        "updated_at": row.updated_at,
    }


async def delete_alert_config(config_id: int, org_id: str) -> bool:
    """Delete an alert config by id (scoped to org_id for safety).

    Returns True if deleted, False if not found.
    Raises RuntimeError if DB is not available.
    """
    if not DB_ENABLED:
        raise RuntimeError("Database not available")

    async with AsyncSessionLocal() as session:
        async with session.begin():
            result = await session.execute(
                alert_configs.delete()
                .where(
                    alert_configs.c.id == config_id,
                    alert_configs.c.org_id == org_id,
                )
                .returning(alert_configs.c.id)
            )
            row = result.first()

    return row is not None


async def list_events(
    org_id: str,
    page: int = 1,
    limit: int = 20,
    event_type: Optional[str] = None,
    is_phishing: Optional[bool] = None,
) -> dict:
    """Return a paginated list of phishing events for an org, most recent first.

    Raises RuntimeError if DB is not available.
    Returns {"items": [...], "total": int, "page": int, "limit": int}.
    """
    if not DB_ENABLED:
        raise RuntimeError("Database not available")

    conditions = [phishing_events.c.org_id == org_id]
    if event_type is not None:
        conditions.append(phishing_events.c.event_type == event_type)
    if is_phishing is not None:
        conditions.append(phishing_events.c.is_phishing == is_phishing)  # noqa: E712

    offset = (page - 1) * limit

    async with AsyncSessionLocal() as session:
        # Total count for this filter
        count_result = await session.execute(
            select(func.count(phishing_events.c.id)).where(*conditions)
        )
        total = count_result.scalar() or 0

        # Fetch the requested page
        result = await session.execute(
            select(
                phishing_events.c.id,
                phishing_events.c.org_id,
                phishing_events.c.event_type,
                phishing_events.c.url,
                phishing_events.c.email_subject,
                phishing_events.c.email_sender,
                phishing_events.c.is_phishing,
                phishing_events.c.confidence,
                phishing_events.c.label,
                phishing_events.c.source,
                phishing_events.c.inference_ms,
                phishing_events.c.created_at,
            )
            .where(*conditions)
            .order_by(phishing_events.c.created_at.desc())
            .offset(offset)
            .limit(limit)
        )
        rows = result.fetchall()

    items = [
        {
            "id": row.id,
            "org_id": row.org_id,
            "event_type": row.event_type,
            "url": row.url,
            "email_subject": row.email_subject,
            "email_sender": row.email_sender,
            "is_phishing": row.is_phishing,
            "confidence": row.confidence,
            "label": row.label,
            "source": row.source,
            "inference_ms": row.inference_ms,
            "created_at": row.created_at,
        }
        for row in rows
    ]

    return {"items": items, "total": total, "page": page, "limit": limit}


async def get_timeline(org_id: str, days: int = 30) -> list:
    """Return daily event counts for the last N days for an org.

    Raises RuntimeError if DB is not available.
    Returns list of {"date": "YYYY-MM-DD", "total": int, "phishing_count": int, "legitimate_count": int}.
    """
    if not DB_ENABLED:
        raise RuntimeError("Database not available")

    from datetime import datetime, timedelta, timezone

    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    day_col = cast(phishing_events.c.created_at, Date)

    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(
                day_col.label("date"),
                func.count(phishing_events.c.id).label("total"),
                func.count(
                    case((phishing_events.c.is_phishing == True, 1))  # noqa: E712
                ).label("phishing_count"),
                func.count(
                    case((phishing_events.c.is_phishing == False, 1))  # noqa: E712
                ).label("legitimate_count"),
            )
            .where(
                phishing_events.c.org_id == org_id,
                phishing_events.c.created_at >= cutoff,
            )
            .group_by(day_col)
            .order_by(day_col)
        )
        rows = result.fetchall()

    return [
        {
            "date": str(row.date),
            "total": row.total,
            "phishing_count": row.phishing_count,
            "legitimate_count": row.legitimate_count,
        }
        for row in rows
    ]


async def get_org_summary(org_id: str) -> dict:
    """Return aggregated statistics for all phishing events belonging to an org.

    Raises RuntimeError if DB is not available.
    """
    if not DB_ENABLED:
        raise RuntimeError("Database not available")

    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(
                func.count(phishing_events.c.id).label("total_events"),
                func.count(
                    case((phishing_events.c.is_phishing == True, 1))  # noqa: E712
                ).label("phishing_count"),
                func.count(
                    case((phishing_events.c.is_phishing == False, 1))  # noqa: E712
                ).label("legitimate_count"),
                func.count(
                    case((phishing_events.c.event_type == "url", 1))
                ).label("url_count"),
                func.count(
                    case((phishing_events.c.event_type == "email", 1))
                ).label("email_count"),
                func.avg(phishing_events.c.confidence).label("avg_confidence"),
                func.max(phishing_events.c.created_at).label("last_event_at"),
            ).where(phishing_events.c.org_id == org_id)
        )
        row = result.first()

    avg_conf = row.avg_confidence
    last_at = row.last_event_at

    return {
        "org_id": org_id,
        "total_events": row.total_events or 0,
        "phishing_count": row.phishing_count or 0,
        "legitimate_count": row.legitimate_count or 0,
        "url_count": row.url_count or 0,
        "email_count": row.email_count or 0,
        "avg_confidence": round(float(avg_conf), 2) if avg_conf is not None else None,
        "last_event_at": last_at,
    }
