# 🚀 FastForge

[![Python](https://img.shields.io/badge/Python-3776AB?logo=python&logoColor=white)](https://www.python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-009485.svg?logo=fastapi&logoColor=white)](https://github.com/fastapi/fastapi)
[![uv](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/uv/main/assets/badge/v0.json)](https://github.com/astral-sh/uv)
[![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)
[![Imports: isort](https://img.shields.io/badge/%20imports-isort-%231674b1?style=flat&labelColor=ef8336)](https://pycqa.github.io/isort/)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-316192?logo=postgresql&logoColor=white)
[![Redis](https://img.shields.io/badge/Redis-%23DD0031.svg?logo=redis&logoColor=white)](https://github.com/redis/redis-py)
[![Docker](https://img.shields.io/badge/Docker-2496ED?logo=docker&logoColor=white)](https://www.docker.com)

FastForge is a lightweight, secure, and scalable FastAPI boilerplate designed for rapid development of authentication-driven applications. It features a robust authentication system with phone-based OTP verification and role-based access control, built with modern Python tools and best practices.

*If you find this project helpful, consider supporting it with a [crypto donation](#-crypto-donations).*


## ✨ Features

- **🔒 Secure Authentication**:
  - Phone-based registration and login with 6-digit OTPs.
  - JWT tokens for session management with configurable expiration.
  - Roles encoded directly in JWT tokens for improved performance (no database lookup required for role checks).
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
  - Pydantic for input validation.
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

To use FastForge as a private repository (recommended for production projects), follow these steps:

1. **Create New Private GitHub Repo**

- On GitHub, make a new private repository (e.g., `my-fastforge`).
- **Do not fork directly** since GitHub doesn't permit changing a public fork to private.

2. **Clone FastForge and Rename Directory**

```bash
git clone https://github.com/javadzarezadeh/fastforge.git my-fastforge
cd my-fastforge
```

3. **Set Your Repo as Git Origin**

- Get your private repo's SSH/HTTPS URL from GitHub.
- Set the origin:

```bash
git remote set-url origin git@github.com:your-username/my-fastforge.git
```

4. **Add FastForge as Upstream Remote**

```bash
git remote add upstream https://github.com/javadzarezadeh/fastforge.git
```

5. **Push Code to Your Repository**

```bash
git push -u origin main
```

6. **Install Dependencies**:
   ```bash
   uv sync
   ```

7. **Set Up Environment Variables**:
   Create a `.env` file in the root directory. The `.env.example` is available as a blueprint.

8. **Set Up PostgreSQL and Redis**:
   - Install PostgreSQL and Redis locally or use Docker (see below).
   - If installing locally, create a database with a name of your choice in PostgreSQL (make sure to update your `.env` file accordingly). When using Docker, the database will be created automatically.

9. **Run Migrations**:
   ```bash
   uv run alembic upgrade head
   ```

10. **Start the Application**:
    ```bash
    uv run fastapi run src/main.py --port 8000 --host 0.0.0.0
    ```

### Keeping Up-to-Date with FastForge

After setting up your private repository, you can keep it up-to-date with the original FastForge repository:

1. **View Remotes for Verification**

```bash
git remote -v
```

You should see:

```
origin    git@github.com:your-username/my-fastforge.git (fetch)
origin    git@github.com:your-username/my-fastforge.git (push)
upstream  https://github.com/javadzarezadeh/fastforge.git (fetch)
upstream  https://github.com/javadzarezadeh/fastforge.git (push)
```

2. **Pull Latest Updates (Without Immediate Commit)**

```bash
git pull --no-commit upstream main
```

- This downloads but does not commit changes, letting you resolve conflicts first.

3. **Resolve Conflicts**

- Open files with conflicts in your editor and fix them as needed.
- After resolving conflicts, stage the resolved files:

```bash
git add .
```

4. **Commit the Merge**

```bash
git commit
```

This approach allows you to keep your customizations while receiving updates from the original boilerplate.

### Docker Setup

1. **Build and Run**:
   ```bash
   docker compose up --build
   ```

2. **Access Services**:
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

### 🔐 Role-Based Access Control

The application implements role-based access control (RBAC) with the following features:

- **Roles in JWT Tokens**: User roles are encoded directly in JWT tokens during authentication, eliminating the need for database lookups during role-based authorization checks for improved performance.
- **Role Assignment**: Users are assigned roles through the `UserRole` many-to-many relationship table.
- **Protected Endpoints**: Endpoints can be protected using the `role_required` dependency, which checks for required roles in the JWT token.
- **Default Roles**: New users are automatically assigned the 'user' role upon registration.
- **Admin Creation**: Admin users can be created via the `/auth/create-admin` endpoint using a secret key.

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
├── docker-entrypoint.sh    # Docker entrypoint script
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


## 💰 Crypto Donations

If you find this project helpful, consider supporting it with a crypto donation:

- **Bitcoin**: `bc1qnk9dvr2zpp42rdrf4td99d3r5g4ylg0wlngpy0`
- **Ethereum**: `0x9D0C185Ed0BbfeFc9dC392D2E3d72Be2635D3BA3`
- **TON**: `UQA6dCXas-TAbpiH7ATdgSxKze1iekkxFz1ch-Z79GwDnFGw`
- **USDT/USDC/DAI (ERC20)**: `0x9D0C185Ed0BbfeFc9dC392D2E3d72Be2635D3BA3`

## ©️ License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
