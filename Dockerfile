FROM python:3.13-slim

# Install uv from official image
COPY --from=ghcr.io/astral-sh/uv:0.8 /uv /uvx /bin/

# Install system dependencies for psycopg[binary] and argon2-cffi
RUN apt-get update && apt-get install -y \
    libpq-dev \
    libargon2-dev \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy project files
COPY pyproject.toml .
COPY uv.lock .
COPY src ./src
COPY migrations ./migrations

# Install dependencies
RUN uv sync --frozen

# Set DOCKER_ENV for migrations
ENV DOCKER_ENV=1

WORKDIR /app/src
CMD ["uv", "run", "fastapi", "run", "main.py", "--host", "0.0.0.0", "--port", "8000", "--workers", "4", "--proxy-headers"]
