# 🚀 FastForge

FastForge is a lightweight, secure, and scalable FastAPI boilerplate designed for rapid development of authentication-driven applications. It features a robust authentication system with phone-based OTP verification and role-based access control, built with modern Python tools and best practices.

## ✨ Features

- **🔒 Secure Authentication**:
  - Phone-based registration and login with 6-digit OTPs.
  - JWT tokens for session management with configurable expiration.
  - Refresh token support for extended sessions with automatic rotation.
  - OTP attempt limiting to prevent brute force attacks.
  - Support for both phone number and email authentication.
  - Phone number change functionality with OTP verification.
  - Email service with mock implementation and user email verification.
- **📏 Scalable Design**:
  - UUIDs for all IDs to ensure uniqueness and scalability in distributed systems.
  - Many-to-many user-role relationships via a `UserRole` table.
  - Redis for OTP storage with configurable TTL for security and efficiency.
  - Connection pooling for database operations.
- **🎯 KISS Principle**:
  - Minimal dependencies and straightforward codebase.
  - Centralized configuration management.
  - Mock SMS service for development (logs OTPs to console).
- **✅ Best Practices**:
  - Pydantic V2 for input validation.
  - SQLModel for ORM with PostgreSQL.
  - Async endpoints for performance.
  - Pre-commit hooks for code quality (Ruff, isort).
  - Comprehensive health checks.
- **⭐ Additional Features**:
  - Soft delete support for user accounts with identifier hashing for privacy.
- **🧪 Testing**:
  - Comprehensive test suite with pytest and pytest-asyncio.
  - Coverage reporting with pytest-cov.

## ⚙️ Configuration

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
- `EMAIL_SERVICE_TYPE`: Type of email service to use (currently only mock is supported)
- `RUNNING_IN_DOCKER`: Environment variable to indicate when running in Docker (automatically set in Dockerfile and docker-compose.yml)

## 🛠️ Prerequisites

- **🐍 Python**: 3.13 or higher
- **🐳 Docker**: Latest version with Docker Compose
- **📦 uv**: Package manager (included in Dockerfile)
- **🗄️ PostgreSQL**: For database (provided via Docker)
- **💾 Redis**: For OTP storage (provided via Docker)

## 🔧 Setup

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
   Create a `.env` file in the root directory. The `.env.example` is available as a blueprint.

4. **Set Up PostgreSQL and Redis**:
   - Install PostgreSQL and Redis locally or use Docker (see below).
   - If installing locally, create a database with a name of your choice in PostgreSQL (make sure to update your `.env` file accordingly). When using Docker, the database will be created automatically.

5. **Run Migrations**:
   ```bash
   uv run alembic upgrade head
   ```

6. **Start the Application**:
   ```bash
   uv run fastapi run src/main.py --port 8000 --host 0.0.0.0
   ```

### Docker Setup

1. **Build and Run**:
   ```bash
   docker compose up --build
   ```

2. **Run Migrations** (in a separate terminal):
   ```bash
   uv run alembic upgrade head
   ```

3. **Access Services**:
   - API: `http://localhost:8000`
   - Adminer (PostgreSQL UI): `http://localhost:8081`

## 📖 Usage

The API provides comprehensive documentation at the following endpoints:
- **Swagger UI**: `http://localhost:8000/docs`
- **ReDoc**: `http://localhost:8000/redoc`

### 🔐 Authentication Flow

The application implements a phone-based OTP authentication system with the following workflow:

1. **Registration/Login**: Users can register or log in using their phone number by requesting an OTP via `POST /auth/request-otp`.

2. **OTP Verification**: After receiving the OTP, users can verify it using either:
   - Form data approach: `POST /auth/login` with phone number as username and OTP as password
   - JSON approach: `POST /auth/verify-login-otp` with phone number and OTP in the request body

3. **JWT Token Generation**: Upon successful OTP verification, the system returns both access and refresh tokens for session management.

4. **Session Management**: The system supports JWT token refresh via the `POST /auth/refresh` endpoint.

5. **Additional Features**:
   - Users can update their email address and verify it with a verification code
   - Users can change their phone number with verification
   - Email and phone verification codes are sent via the configured service

### 👤 User Management

The application provides endpoints for user management, including viewing and updating user information, with role-based access control for administrative functions.

### 🔍 Finding OTPs

OTPs are logged by the `MockSMSService`:

- **Local**: Check terminal output for `INFO:root:Mock SMS: Sending OTP <6-digit-otp> to <phone_number>`.
- **Docker**: Run `docker compose logs app` and look for the same message.
- **Example**: `2025-08-17 05:30:00 [INFO] root: Mock SMS: Sending OTP 123456 to +1234567890`.

## 🧪 Testing

1. **Run Tests**:
   ```bash
   uv run pytest tests/ --cov=src --cov-report=html
   ```
   - Generates coverage report in `htmlcov/`.

2. **Check Code Quality**:
   ```bash
   uv run pre-commit run --all-files
   ```

## 🏗️ Project Structure

```
fastforge/
├── src/
│   ├── __init__.py
│   ├── main.py             # FastAPI app, health checks and main configuration
│   ├── auth.py             # Authentication logic and helper functions (OTP, JWT)
│   ├── database.py         # Database configuration
│   ├── sms_service.py      # SMS service interface and implementations
│   ├── email_service.py    # Email service interface and implementations
│   ├── config.py           # Centralized configuration management
│   ├── models/
│   │   ├── __init__.py
│   │   ├── user.py         # User, Role and UserRole models
│   ├── routes/
│   │   ├── __init__.py
│   │   ├── auth.py         # Authentication endpoints (OTP, JWT)
│   │   ├── users.py        # User management endpoints
│   │   ├── roles.py        # Role management endpoints
├── migrations/             # Alembic migrations
├── tests/
│   ├── test_auth.py        # Authentication tests
│   ├── test_health.py      # Health check tests
├── .env                    # Environment variables
├── .env.example            # Example environment variables
├── pyproject.toml          # Dependencies
├── uv.lock                 # Locked dependencies
├── Dockerfile              # Docker configuration
├── docker-compose.yml      # Docker Compose services
├── .pre-commit-config.yaml # Code quality hooks
├── README.md               # Project documentation
```

## 📦 Dependencies

- **FastAPI**: Web framework
- **SQLModel**: ORM for PostgreSQL
- **psycopg**: PostgreSQL driver
- **redis**: OTP storage
- **python-jose**: JWT handling
- **pydantic**: Input validation
- **alembic**: Database migrations
- **uv**: Package management
- **pytest**: Testing framework

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Commit changes: `git commit -m "Add your feature"`
4. Run pre-commit hooks: `uv run pre-commit run --all-files`
5. Push to branch: `git push origin feature/your-feature`
6. Open a pull request

## ©️ License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
