"""
Database module — PostgreSQL connection and schema definitions.

Provides:
- Async SQLAlchemy engine / session factory
- Table metadata (organisations, phishing_events, alert_configs)
- init_db() to create tables on first run
"""

import os
import logging

from sqlalchemy import (
    BigInteger,
    Boolean,
    Column,
    Float,
    MetaData,
    String,
    Table,
    Text,
    TIMESTAMP,
    Integer,
    func,
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
