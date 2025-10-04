FROM python:3.13-slim

# Install uv from official image
COPY --from=ghcr.io/astral-sh/uv:0.8 /uv /uvx /bin/

# Install system dependencies for psycopg[binary] and argon2-cffi
RUN apt-get update && apt-get install -y \
    libpq-dev \
    libargon2-dev \
    build-essential \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --shell /bin/bash app

WORKDIR /app

# Copy project files
COPY pyproject.toml .
COPY uv.lock .
COPY src ./src
COPY migrations ./migrations
COPY tests ./tests

# Install dependencies
RUN uv sync --frozen --no-cache && \
    uv sync --frozen --no-cache --group dev

# Set DOCKER_ENV for migrations
ENV DOCKER_ENV=1

# Change ownership to app user
RUN chown -R app:app /app
USER app

EXPOSE 8000

CMD ["uv", "run", "fastapi", "run", "src/main.py", "--port", "8000", "--host", "0.0.0.0"]
