#!/bin/sh

# Run database migrations
uv run alembic upgrade head

# Start the FastAPI application
uv run fastapi run src/main.py --port 8000 --host 0.0.0.0
