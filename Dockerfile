FROM python:3.13-slim

# Install uv from official image
COPY --from=ghcr.io/astral-sh/uv:0.9.2 /uv /uvx /bin/

RUN useradd --create-home --shell /bin/bash app

# Set environment variable to indicate running in Docker
ENV RUNNING_IN_DOCKER=true

WORKDIR /app

# Copy dependency files first for better layer caching
COPY pyproject.toml uv.lock ./

# Install dependencies
RUN uv sync --frozen --no-cache && \
    uv sync --frozen --no-cache --group dev

# Copy application code
COPY alembic.ini .
COPY src ./src
COPY migrations ./migrations
COPY tests ./tests

# Copy entrypoint script
COPY docker-entrypoint.sh .
RUN chmod +x docker-entrypoint.sh

# Change ownership to app user
RUN chown -R app:app /app
USER app

EXPOSE 8000

ENTRYPOINT ["sh", "-c", "./docker-entrypoint.sh"]
