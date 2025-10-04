from typing import Generator

from sqlmodel import Session, create_engine

from .config import Config

# Get database URL from config
DATABASE_URL = Config.get_database_url()

# Configure connection pooling
engine = create_engine(
    DATABASE_URL,
    echo=Config.DEBUG,
    pool_size=20,  # Number of connection objects to maintain in the pool
    max_overflow=30,  # Number of connections that can be created beyond pool_size
    pool_pre_ping=True,  # Verify connections before use
    pool_recycle=3600,  # Recycle connections after 1 hour
)


def get_session() -> Generator[Session, None]:
    """
    Dependency to get a database session.

    Yields:
        Session: A database session that is automatically closed after use
    """
    with Session(engine) as session:
        yield session
