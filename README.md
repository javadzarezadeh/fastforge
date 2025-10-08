# FastForge

FastForge is a lightweight, secure, and scalable FastAPI boilerplate designed for rapid development of authentication-driven applications. It features a robust authentication system with phone-based OTP verification, password login, and role-based access control, built with modern Python tools and best practices.

## Features

- **Secure Authentication**:
  - Phone-based registration and login with 6-digit OTPs (custom-generated, no external TOTP libraries).
  - Password authentication using Argon2 for hashing.
  - JWT tokens for session management with configurable expiration.
  - Refresh token support for extended sessions with automatic rotation.
  - OTP attempt limiting (max 3 attempts per 15 minutes window) to prevent brute force attacks.
  - Support for both phone number and email authentication.
- **Scalable Design**:
  - UUIDs for all IDs to ensure uniqueness and scalability in distributed systems.
  - Many-to-many user-role relationships via a `UserRole` table.
  - Redis for OTP storage with configurable TTL for security and efficiency.
  - Connection pooling for database operations.
- **KISS Principle**:
 - Minimal dependencies and straightforward codebase.
  - Centralized configuration management.
  - Mock SMS service for development (logs OTPs to console).
- **Best Practices**:
  - Pydantic V2 for input validation.
  - SQLModel for ORM with PostgreSQL.
  - Async endpoints for performance.
 - Pre-commit hooks for code quality (Ruff, isort).
  - Comprehensive health checks.
  - Rate limiting on authentication endpoints (3 requests per minute).
- **Testing**:
  - Comprehensive test suite with pytest and pytest-asyncio.
  - Coverage reporting with pytest-cov.

## Configuration

The application uses a centralized configuration system via the `src/config.py` module. Key configuration variables:

- `APP_NAME`: Application name
- `DEBUG`: Enable debug mode
- `SECRET_KEY`: JWT secret key (required)
- `ADMIN_SECRET_KEY`: Secret key for creating admin users
- `ACCESS_TOKEN_EXPIRE_MINUTES`: JWT expiration time
- `OTP_EXPIRE_MINUTES`: OTP expiration time
- `DATABASE_URL`: Database connection string
- `REDIS_URL`: Redis connection string
- `ALLOWED_ORIGINS`: Comma-separated list of allowed origins for CORS
- `ENV`: Environment (development/production)
- `SMS_SERVICE_TYPE`: Type of SMS service to use (mock, twilio, etc.)

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

2. **Run Migrations** (in a separate terminal):
   ```bash
   uv run alembic upgrade head
   ```

3. **Access Services**:
   - API: `http://localhost:8000`
   - Adminer (PostgreSQL UI): `http://localhost:8081`

## Usage

### Authentication Endpoints

1. **Request OTP**:
   - Endpoint: `POST /auth/request-otp`
   - Body: `{"phone_number": "+1234567890"}`
   - Response: `{"message": "OTP sent for login or registration"}`
   - OTP is logged to console (or Docker logs: `docker-compose logs app`).

2. **Login with OTP** (using form data):
   - Endpoint: `POST /auth/login`
   - Body: `{"username": "+1234567890", "password": "123456"}` (phone number as username, OTP as password)
   - Response: `{"access_token": "<jwt>", "refresh_token": "<refresh_token>", "token_type": "bearer"}`
   - Supports both phone number and email login if user has added an email

3. **Verify Login OTP** (using JSON):
   - Endpoint: `POST /auth/verify-login-otp`
   - Body: `{"phone_number": "+1234567890", "otp": "123456", "email": "user@example.com"}` (email is optional)
   - Response: `{"access_token": "<jwt>", "refresh_token": "<refresh_token>", "token_type": "bearer"}`

4. **Refresh Access Token**:
   - Endpoint: `POST /auth/refresh`
   - Body: `{"refresh_token": "<refresh_token>"}`
   - Response: `{"access_token": "<new_jwt>", "refresh_token": "<new_refresh_token>", "token_type": "bearer"}`

5. **Update User Email**:
   - Endpoint: `POST /auth/update-email`
   - Requires: Valid JWT token
   - Body: `{"email": "user@example.com"}`
   - Response: `{"message": "Email updated. Verification code sent to email."}`

6. **Verify User Email**:
   - Endpoint: `POST /auth/verify-email`
   - Requires: Valid JWT token
   - Body: `{"verification_code": "123456"}`
   - Response: `{"message": "Email verified successfully"}`

7. **Health Check**:
   - Basic: `GET /health` - Response: `{"status": "ok"}`
   - Extended: `GET /health/extended` - Response: Detailed health status with database and Redis connectivity

### User Management Endpoints

1. **Get Current User**:
   - Endpoint: `GET /users/me`
   - Requires: Valid JWT token
   - Response: Current user's information

2. **Update Current User**:
   - Endpoint: `PUT /users/me`
   - Requires: Valid JWT token
   - Body: User update information

3. **Delete Current User**:
   - Endpoint: `DELETE /users/me`
   - Requires: Valid JWT token

4. **Get User by ID** (Admin only):
   - Endpoint: `GET /users/{user_id}`
   - Requires: Valid JWT token with admin role

### Role Management Endpoints (Admin only)

1. **List Roles**:
   - Endpoint: `GET /roles/`
   - Requires: Valid JWT token with admin role

2. **Create Role**:
   - Endpoint: `POST /roles/`
   - Requires: Valid JWT token with admin role
   - Body: `{"name": "new_role_name"}`

### Finding OTPs
- OTPs are logged by the `MockSMSService`:
  - **Local**: Check terminal output for `INFO:root:Mock SMS: Sending OTP <6-digit-otp> to <phone_number>`.
  - **Docker**: Run `docker-compose logs app` and look for the same message.
  - Example: `2025-08-17 05:30:00 [INFO] root: Mock SMS: Sending OTP 123456 to +1234567890`.

### Example Commands

```bash
# Request OTP for login or registration
curl -X POST "http://localhost:8000/auth/request-otp" -H "Content-Type: application/json" -d '{"phone_number": "+1234567890"}'

# Verify OTP and get JWT token (using JSON)
curl -X POST "http://localhost:8000/auth/verify-login-otp" -H "Content-Type: application/json" -d '{"phone_number": "+1234567890", "otp": "123456"}'

# Login with OTP (using form data) - supports both phone and email login
curl -X POST "http://localhost:8000/auth/login" -H "Content-Type: application/x-www-form-urlencoded" -d 'username=+1234567890&password=123456'

# Refresh access token
curl -X POST "http://localhost:8000/auth/refresh" -H "Content-Type: application/json" -d '{"refresh_token": "your-refresh-token-here"}'

# Update user email (requires JWT token)
curl -X POST "http://localhost:8000/auth/update-email" -H "Content-Type: application/json" -H "Authorization: Bearer <your-jwt-token>" -d '{"email": "user@example.com"}'

# Verify user email (requires JWT token)
curl -X POST "http://localhost:8000/auth/verify-email" -H "Content-Type: application/json" -H "Authorization: Bearer <your-jwt-token>" -d '{"verification_code": "123456"}'

# Get current user info (requires JWT token)
curl -X GET "http://localhost:8000/users/me" -H "Authorization: Bearer <your-jwt-token>"

# Health check
curl -X GET "http://localhost:8000/health"

# Extended health check
curl -X GET "http://localhost:8000/health/extended"
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
│   ├── main.py           # FastAPI app, health checks and main configuration
│   ├── auth.py           # Authentication logic and helper functions (OTP, JWT, password)
│   ├── database.py       # Database configuration
│   ├── sms_service.py    # SMS service interface and implementations
│   ├── config.py         # Centralized configuration management
│   ├── models/
│   │   ├── __init__.py
│   │   ├── user.py       # User model with UUID
│   │   ├── role.py       # Role and UserRole models
│   ├── routes/
│   │   ├── __init__.py
│   │   ├── auth.py       # Authentication endpoints (OTP, JWT, password)
│   │   ├── users.py      # User management endpoints
│   │   ├── roles.py      # Role management endpoints
├── migrations/            # Alembic migrations
├── tests/
│   ├── test_auth.py      # Authentication tests
│   ├── test_health.py    # Health check tests
├── .env                  # Environment variables
├── .env.example          # Example environment variables
├── pyproject.toml        # Dependencies
├── uv.lock               # Locked dependencies
├── Dockerfile            # Docker configuration
├── docker-compose.yml    # Docker Compose services
├── .pre-commit-config.yaml # Code quality hooks
├── README.md             # Project documentation
```

## Dependencies

- **FastAPI**: Web framework
- **SQLModel**: ORM for PostgreSQL
- **psycopg**: PostgreSQL driver
- **redis**: OTP storage
- **argon2-cffi**: Password hashing
- **python-jose**: JWT handling
- **pydantic**: Input validation
- **alembic**: Database migrations
- **uv**: Package management
- **pytest**: Testing framework

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Commit changes: `git commit -m "Add your feature"`
4. Run pre-commit hooks: `uv run pre-commit run --all-files`
5. Push to branch: `git push origin feature/your-feature`
6. Open a pull request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
