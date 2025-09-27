from unittest.mock import Mock, patch

import pytest
import redis
from fastapi.testclient import TestClient
from sqlmodel import Session, SQLModel, create_engine, select

from src.auth import create_access_token
from src.main import app, get_session
from src.models.user import Role, User, UserRole
from src.sms_service import MockSMSService

# In-memory SQLite database for testing
DATABASE_URL = "sqlite:///:memory:"
engine = create_engine(DATABASE_URL, echo=False)


# Override get_session for tests
def override_get_session():
    with Session(engine) as session:
        yield session


app.dependency_overrides[get_session] = override_get_session


# Create tables before tests
@pytest.fixture(autouse=True)
def setup_database():
    SQLModel.metadata.create_all(engine)
    yield
    SQLModel.metadata.drop_all(engine)


# Mock Redis client
@pytest.fixture
def mock_redis():
    mock = Mock(spec=redis.Redis)
    mock.setex = Mock()
    mock.get = Mock()
    mock.delete = Mock()
    return mock


# Mock SMS service
@pytest.fixture
def mock_sms_service():
    return Mock(spec=MockSMSService)


# Test client
@pytest.fixture
def client():
    return TestClient(app)


# Create admin user
@pytest.fixture
def admin_user():
    with Session(engine) as session:
        admin_role = Role(name="admin")
        session.add(admin_role)
        user = User(phone_number="+1234567890", email="admin@example.com")
        session.add(user)
        session.commit()
        session.refresh(user)
        session.refresh(admin_role)
        user_role = UserRole(user_id=user.id, role_id=admin_role.id)
        session.add(user_role)
        session.commit()
        return user


# Test POST /auth/request-otp
def test_request_otp_success(client, mock_redis, mock_sms_service):
    with (
        patch("src.auth.redis_client", mock_redis),
        patch("src.sms_service.MockSMSService", return_value=mock_sms_service),
    ):
        response = client.post("/auth/request-otp", json={"phone_number": "+3223456"})
        assert response.status_code == 200
        assert response.json() == {"message": "OTP sent for login or registration"}
        mock_redis.setex.assert_called_once()
        mock_sms_service.send_otp.assert_called_once_with(
            "+3223456", mock_redis.setex.call_args[0][1]
        )


# Test POST /auth/login - Request OTP
def test_login_request_otp(client, mock_redis, mock_sms_service):
    with (
        patch("src.auth.redis_client", mock_redis),
        patch("src.sms_service.MockSMSService", return_value=mock_sms_service),
    ):
        response = client.post("/auth/login", data={"username": "+3223456"})
        assert response.status_code == 200
        assert response.json() == {"message": "OTP sent for login or registration"}
        mock_redis.setex.assert_called_once()
        mock_sms_service.send_otp.assert_called_once_with(
            "+3223456", mock_redis.setex.call_args[0][1]
        )


# Test POST /auth/login - Valid OTP, new user
def test_login_valid_otp_new_user(client, mock_redis, mock_sms_service):
    mock_redis.get.return_value = "907816"
    with (
        patch("src.auth.redis_client", mock_redis),
        patch("src.sms_service.MockSMSService", return_value=mock_sms_service),
    ):
        response = client.post(
            "/auth/login", data={"username": "+3223456", "password": "907816"}
        )
        assert response.status_code == 200
        assert "access_token" in response.json()
        assert response.json()["token_type"] == "bearer"
        mock_redis.delete.assert_called_once_with("otp:+3223456")

        # Verify user creation
        with Session(engine) as session:
            user = session.exec(
                select(User).where(User.phone_number == "+3223456")
            ).first()
            assert user is not None
            assert user.phone_number == "+3223456"
            assert user.email is None
            assert user.hashed_password is None

            assert "user" in [role.name for role in user.roles]


# Test POST /auth/login - Valid OTP, existing user
def test_login_valid_otp_existing_user(client, mock_redis, mock_sms_service):
    # Create user
    with Session(engine) as session:
        user_role = Role(name="user")

        session.add(user_role)

        user = User(phone_number="+3223456", email=None, hashed_password=None)
        session.add(user)
        session.commit()

        session.refresh(user)

        session.refresh(user_role)

        user_role_link = UserRole(user_id=user.id, role_id=user_role.id)

        session.add(user_role_link)

        session.commit()

    mock_redis.get.return_value = "907816"
    with (
        patch("src.auth.redis_client", mock_redis),
        patch("src.sms_service.MockSMSService", return_value=mock_sms_service),
    ):
        response = client.post(
            "/auth/login", data={"username": "+3223456", "password": "907816"}
        )
        assert response.status_code == 200
        assert "access_token" in response.json()
        assert response.json()["token_type"] == "bearer"
        mock_redis.delete.assert_called_once_with("otp:+3223456")


# Test POST /auth/login - Invalid OTP
def test_login_invalid_otp(client, mock_redis, mock_sms_service):
    mock_redis.get.return_value = "123456"
    with (
        patch("src.auth.redis_client", mock_redis),
        patch("src.sms_service.MockSMSService", return_value=mock_sms_service),
    ):
        response = client.post(
            "/auth/login", data={"username": "+3223456", "password": "907816"}
        )
        assert response.status_code == 401
        assert response.json()["detail"] == "Invalid OTP"
        mock_redis.delete.assert_not_called()


# Test POST /auth/verify-login-otp - Valid OTP, new user
def test_verify_login_otp_new_user(client, mock_redis, mock_sms_service):
    mock_redis.get.return_value = "907816"
    with (
        patch("src.auth.redis_client", mock_redis),
        patch("src.sms_service.MockSMSService", return_value=mock_sms_service),
    ):
        response = client.post(
            "/auth/verify-login-otp",
            json={"phone_number": "+3223456", "otp": "907816", "email": None},
        )
        assert response.status_code == 200
        assert "access_token" in response.json()
        assert response.json()["token_type"] == "bearer"
        mock_redis.delete.assert_called_once_with("otp:+3223456")

        # Verify user creation
        with Session(engine) as session:
            user = session.exec(
                select(User).where(User.phone_number == "+3223456")
            ).first()
            assert user is not None
            assert user.phone_number == "+3223456"
            assert user.email is None
            assert user.hashed_password is None
            assert "user" in [role.name for role in user.roles]


# Test POST /auth/verify-login-otp - Valid OTP, existing user
def test_verify_login_otp_existing_user(client, mock_redis, mock_sms_service):
    # Create user
    with Session(engine) as session:
        user_role = Role(name="user")

        session.add(user_role)
        user = User(phone_number="+3223456", email=None, hashed_password=None)
        session.add(user)
        session.commit()
        session.refresh(user)
        session.refresh(user_role)
        user_role_link = UserRole(user_id=user.id, role_id=user_role.id)
        session.add(user_role_link)
        session.commit()

    mock_redis.get.return_value = "907816"
    with (
        patch("src.auth.redis_client", mock_redis),
        patch("src.sms_service.MockSMSService", return_value=mock_sms_service),
    ):
        response = client.post(
            "/auth/verify-login-otp",
            json={"phone_number": "+3223456", "otp": "907816", "email": None},
        )
        assert response.status_code == 200
        assert "access_token" in response.json()
        assert response.json()["token_type"] == "bearer"
        mock_redis.delete.assert_called_once_with("otp:+3223456")


# Test POST /auth/verify-login-otp - Invalid OTP
def test_verify_login_otp_invalid_otp(client, mock_redis, mock_sms_service):
    mock_redis.get.return_value = "123456"
    with (
        patch("src.auth.redis_client", mock_redis),
        patch("src.sms_service.MockSMSService", return_value=mock_sms_service),
    ):
        response = client.post(
            "/auth/verify-login-otp",
            json={"phone_number": "+3223456", "otp": "907816", "email": None},
        )
        assert response.status_code == 401
        assert response.json()["detail"] == "Invalid OTP"
        mock_redis.delete.assert_not_called()


# Test rate-limiting on /auth/request-otp
def test_request_otp_rate_limit(client, mock_redis, mock_sms_service):
    with (
        patch("src.auth.redis_client", mock_redis),
        patch("src.sms_service.MockSMSService", return_value=mock_sms_service),
    ):
        for _ in range(5):
            response = client.post(
                "/auth/request-otp", json={"phone_number": "+3223456"}
            )
            assert response.status_code == 200
        response = client.post("/auth/request-otp", json={"phone_number": "+3223456"})
        assert response.status_code == 429
        assert "Rate limit exceeded" in response.json()["detail"]


# Test rate-limiting on /auth/login
def test_login_rate_limit(client, mock_redis, mock_sms_service):
    with (
        patch("src.auth.redis_client", mock_redis),
        patch("src.sms_service.MockSMSService", return_value=mock_sms_service),
    ):
        for _ in range(5):
            response = client.post("/auth/login", data={"username": "+3223456"})
            assert response.status_code == 200
        response = client.post("/auth/login", data={"username": "+3223456"})
        assert response.status_code == 429
        assert "Rate limit exceeded" in response.json()["detail"]


# Test rate-limiting on /auth/verify-login-otp
def test_verify_login_otp_rate_limit(client, mock_redis, mock_sms_service):
    with (
        patch("src.auth.redis_client", mock_redis),
        patch("src.sms_service.MockSMSService", return_value=mock_sms_service),
    ):
        for _ in range(5):
            response = client.post(
                "/auth/verify-login-otp",
                json={"phone_number": "+3223456", "otp": "907816", "email": None},
            )
            assert response.status_code == 401  # Invalid OTP, but request goes through
        response = client.post(
            "/auth/verify-login-otp",
            json={"phone_number": "+3223456", "otp": "907816", "email": None},
        )
        assert response.status_code == 429
        assert "Rate limit exceeded" in response.json()["detail"]


# Test admin-only endpoint /users/{user_id}
def test_get_user_by_id_admin(client, admin_user, mock_redis, mock_sms_service):
    # Create a non-admin user
    with Session(engine) as session:
        user_role = Role(name="user")
        session.add(user_role)
        user = User(phone_number="+3223456", email=None, hashed_password=None)
        session.add(user)
        session.commit()
        session.refresh(user)
        session.refresh(user_role)
        user_role_link = UserRole(user_id=user.id, role_id=user_role.id)
        session.add(user_role_link)
        session.commit()

    # Get JWT for admin
    admin_token = create_access_token({"sub": admin_user.phone_number})

    # Test admin access
    response = client.get(
        f"/users/{user.id}", headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert response.status_code == 200
    assert response.json() == {
        "id": str(user.id),
        "phone_number": "+3223456",
        "email": None,
        "roles": ["user"],
    }


# Test /users/{user_id} - Non-admin access
def test_get_user_by_id_non_admin(client, mock_redis, mock_sms_service):
    # Create a non-admin user
    with Session(engine) as session:
        user_role = Role(name="user")
        session.add(user_role)
        user = User(phone_number="+3223456", email=None, hashed_password=None)
        session.add(user)
        session.commit()
        session.refresh(user)
        session.refresh(user_role)
        user_role_link = UserRole(user_id=user.id, role_id=user_role.id)
        session.add(user_role_link)
        session.commit()

    # Get JWT for non-admin
    user_token = create_access_token({"sub": user.phone_number})

    # Test non-admin access
    response = client.get(
        f"/users/{user.id}", headers={"Authorization": f"Bearer {user_token}"}
    )
    assert response.status_code == 403
    assert response.json()["detail"] == "Requires one of: admin"
