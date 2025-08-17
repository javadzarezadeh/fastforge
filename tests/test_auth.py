import pytest
from httpx import AsyncClient
from sqlmodel import Session, SQLModel, create_engine
from sqlmodel.pool import StaticPool

from src.auth import hash_password
from src.database import get_session
from src.main import app
from src.models.user import User


@pytest.fixture(name="session")
def session_fixture():
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    SQLModel.metadata.create_all(engine)
    with Session(engine) as session:
        yield session


@pytest.fixture(name="client")
async def client_fixture(session: Session):
    def get_session_override():
        return session

    app.dependency_overrides[get_session] = get_session_override
    async with AsyncClient(app=app, base_url="http://test") as client:
        yield client
    app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_register(client: AsyncClient):
    response = await client.post(
        "/auth/register", json={"phone_number": "+1234567890", "password": "mypassword"}
    )
    assert response.status_code == 200
    assert response.json()["message"] == "OTP sent for phone verification"


@pytest.mark.asyncio
async def test_verify_otp(client: AsyncClient, session: Session):
    # Simulate OTP storage in Redis (mocked)
    from src.auth import store_otp

    store_otp("+1234567890", "123456")
    response = await client.post(
        "/auth/verify-otp", json={"phone_number": "+1234567890", "otp": "123456"}
    )
    assert response.status_code == 200
    assert "access_token" in response.json()


@pytest.mark.asyncio
async def test_login_password(client: AsyncClient, session: Session):
    # Create user
    user = User(phone_number="+1234567890", hashed_password=hash_password("mypassword"))
    session.add(user)
    session.commit()

    response = await client.post(
        "/auth/login", json={"phone_number": "+1234567890", "password": "mypassword"}
    )
    assert response.status_code == 200
    assert "access_token" in response.json()


@pytest.mark.asyncio
async def test_login_otp(client: AsyncClient, session: Session):
    # Create user
    user = User(phone_number="+1234567890")
    session.add(user)
    session.commit()

    response = await client.post("/auth/login", json={"phone_number": "+1234567890"})
    assert response.status_code == 200
    assert response.json()["message"] == "OTP sent for login"

    # Verify OTP (mock OTP is logged, use "123456" for testing)
    response = await client.post(
        "/auth/verify-login-otp", json={"phone_number": "+1234567890", "otp": "123456"}
    )
    assert response.status_code == 200
    assert "access_token" in response.json()
