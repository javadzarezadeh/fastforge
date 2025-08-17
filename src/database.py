import os

from dotenv import load_dotenv
from sqlmodel import Session, create_engine

load_dotenv()

DATABASE_URL = (
    os.getenv("DATABASE_URL")
    if not os.getenv("DOCKER_ENV")
    else "postgresql+psycopg://postgres:password@db:5432/fastforge"
)
engine = create_engine(DATABASE_URL, echo=os.getenv("DEBUG") == "true")


def get_session():
    with Session(engine) as session:
        yield session
