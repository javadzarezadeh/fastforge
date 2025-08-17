# FastForge

FastForge is a lightweight, secure, and scalable FastAPI boilerplate designed for rapid development of authentication-driven applications. It features a robust authentication system with phone-based OTP verification, password login, and role-based access control, built with modern Python tools and best practices.

## Features

- **Secure Authentication**:
  - Phone-based registration and login with 6-digit OTPs (custom-generated, no external TOTP libraries).
  - Password authentication using Argon2 for hashing.
  - JWT tokens for session management with configurable expiration.
- **Scalable Design**:
  - UUIDs for all IDs to ensure uniqueness and scalability in distributed systems.
  - Many-to-many user-role relationships via a `UserRole` table.
  - Redis for OTP storage with 5-minute TTL for security and efficiency.
- **KISS Principle**:
  - Minimal dependencies and straightforward codebase.
  - Mock SMS service for development (logs OTPs to console).
- **Best Practices**:
  - Pydantic V2 for input validation.
  - SQLModel for ORM with PostgreSQL.
  - Async endpoints for performance.
  - Pre-commit hooks for code quality (Ruff, isort).
- **Testing**:
  - Comprehensive test suite with pytest and pytest-asyncio.
  - Coverage reporting with pytest-cov.

## Prerequisites

- **Python**: 3.12 or higher
- **Docker**: Latest version with Docker Compose
- **uv**: Package manager (included in Dockerfile)
- **PostgreSQL**: For database (provided via Docker)
- **Redis**: For OTP storage (provided via Docker)

## Setup

### Local Setup

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/javadzarezadeh/fastforge.git
   cd fastforge
   ```

2. **Install Dependencies**:
   ```bash
   uv sync
   ```

3. **Set Up Environment Variables**:
   Create a `.env` file in the root directory:
   ```env
   APP_NAME="FastForge"
   DEBUG=true
   SECRET_KEY="your-secure-random-key-here"  # Generate with: python -c "import secrets; print(secrets.token_hex(32))"
   DATABASE_URL="postgresql+psycopg://postgres:password@localhost:5432/fastforge"
   REDIS_URL="redis://localhost:6379/0"
   LOG_LEVEL="INFO"
   ALLOWED_ORIGINS="http://localhost:3000,https://myapp.com"
   ```

4. **Set Up PostgreSQL and Redis**:
   - Install PostgreSQL and Redis locally or use Docker (see below).
   - Create a database named `fastforge` in PostgreSQL.

5. **Run Migrations**:
   ```bash
   uv run alembic upgrade head
   ```

6. **Start the Application**:
   ```bash
   uv run fastapi run src/main.py
   ```

### Docker Setup

1. **Build and Run**:
   ```bash
   docker-compose up --build
   ```

2. **Run Migrations**:
   ```bash
   docker-compose up -d db
   uv run alembic revision --autogenerate -m "Initial migration"
   uv run alembic upgrade head
   ```

3. **Access Services**:
   - API: `http://localhost:8000`
   - Adminer (PostgreSQL UI): `http://localhost:8081`
   - Redis: Port `6379` (internal to Docker network)

## Usage

### Authentication Endpoints

1. **Register**:
   - Endpoint: `POST /auth/register`
   - Body: `{"phone_number": "+1234567890", "password": "mypassword"}`
   - Response: `{"message": "OTP sent", "phone_number": "+1234567890"}`
   - OTP is logged to console (or Docker logs: `docker-compose logs app`).

2. **Verify OTP (Register)**:
   - Endpoint: `POST /auth/verify-otp`
   - Body: `{"phone_number": "+1234567890", "otp": "123456"}`
   - Response: `{"access_token": "<jwt>", "token_type": "bearer"}`

3. **Login**:
   - **With Password**:
     - Endpoint: `POST /auth/login`
     - Body: `{"phone_number": "+1234567890", "password": "mypassword"}`
     - Response: `{"access_token": "<jwt>", "token_type": "bearer"}`
   - **With OTP**:
     - Endpoint: `POST /auth/login`
     - Body: `{"phone_number": "+1234567890"}`
     - Response: `{"message": "OTP sent"}`
     - Check logs for OTP.

4. **Verify OTP (Login)**:
   - Endpoint: `POST /auth/verify-login-otp`
   - Body: `{"phone_number": "+1234567890", "otp": "123456"}`
   - Response: `{"access_token": "<jwt>", "token_type": "bearer"}`

5. **Health Check**:
   - Endpoint: `GET /health`
   - Response: `{"status": "ok"}`

### Finding OTPs
- OTPs are logged by the `MockSMSService`:
  - **Local**: Check terminal output for `INFO:root:Mock SMS: Sending OTP <6-digit-otp> to <phone_number>`.
  - **Docker**: Run `docker-compose logs app` and look for the same message.
  - Example: `2025-08-17 05:30:00 [INFO] root: Mock SMS: Sending OTP 123456 to +1234567890`.

### Example Commands

```bash
# Register
curl -X POST "http://localhost:8000/auth/register" -H "Content-Type: application/json" -d '{"phone_number": "+1234567890", "password": "mypassword"}'

# Verify OTP
curl -X POST "http://localhost:8000/auth/verify-otp" -H "Content-Type: application/json" -d '{"phone_number": "+1234567890", "otp": "123456"}'

# Login with Password
curl -X POST "http://localhost:8000/auth/login" -H "Content-Type: application/json" -d '{"phone_number": "+1234567890", "password": "mypassword"}'

# Login with OTP
curl -X POST "http://localhost:8000/auth/login" -H "Content-Type: application/json" -d '{"phone_number": "+1234567890"}'
curl -X POST "http://localhost:8000/auth/verify-login-otp" -H "Content-Type: application/json" -d '{"phone_number": "+1234567890", "otp": "123456"}'
```

## Testing

1. **Run Tests**:
   ```bash
   uv run pytest tests/ --cov=src --cov-report=html
   ```
   - Generates coverage report in `htmlcov/`.

2. **Check Code Quality**:
   ```bash
   uv run pre-commit run --all-files
   ```

## Project Structure

```
fastforge/
├── src/
│   ├── __init__.py
│   ├── main.py           # FastAPI app and endpoints
│   ├── auth.py           # Authentication logic (OTP, JWT, password)
│   ├── database.py       # Database configuration
│   ├── sms_service.py    # Mock SMS service
│   ├── models/
│   │   ├── __init__.py
│   │   ├── user.py       # User model with UUID
│   │   ├── role.py       # Role and UserRole models
├── migrations/            # Alembic migrations
├── tests/
│   ├── test_auth.py      # Authentication tests
├── .env                  # Environment variables
├── pyproject.toml        # Dependencies
├── uv.lock               # Locked dependencies
├── Dockerfile            # Docker configuration
├── docker-compose.yml    # Docker Compose services
├── .pre-commit-config.yaml # Code quality hooks
```

## Dependencies

- **FastAPI**: Web framework
- **SQLModel**: ORM for PostgreSQL
- **psycopg**: PostgreSQL driver
- **redis[hiredis]**: OTP storage
- **argon2-cffi**: Password hashing
- **python-jose**: JWT handling
- **pydantic**: Input validation
- **alembic**: Database migrations
- **uv**: Package management
- **pytest**: Testing framework
- **pre-commit**: Code quality checks

## Contributing

1. Fork the repository.
2. Create a feature branch: `git checkout -b feature/your-feature`.
3. Commit changes: `git commit -m "Add your feature"`.
4. Run pre-commit hooks: `uv run pre-commit run --all-files`.
5. Push to branch: `git push origin feature/your-feature`.
6. Open a pull request.

## License

MIT License

Copyright (c) 2025 FastForge Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
