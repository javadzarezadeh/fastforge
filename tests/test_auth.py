import os

os.environ["TESTING"] = "True"

import os
import sys

from fastapi.testclient import TestClient

sys.path.append(os.path.join(os.path.dirname(__file__), ".."))

from src.config import Config
from src.main import app


def test_health_check():
    client = TestClient(app)
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_extended_health_check():
    client = TestClient(app)
    response = client.get("/health/extended")
    assert response.status_code == 200
    data = response.json()
    assert "status" in data
    assert "checks" in data
    assert "timestamp" in data


def test_request_otp_endpoint():
    client = TestClient(app)
    # Test with valid phone number
    response = client.post("/auth/request-otp", json={"phone_number": "+1234567890"})
    # Should return success since we're using mock SMS service
    assert response.status_code == 200
    assert "message" in response.json()


def test_config_values():
    # Test that default config values are properly loaded
    assert Config.ACCESS_TOKEN_EXPIRE_MINUTES > 0
    assert Config.OTP_EXPIRE_MINUTES > 0
