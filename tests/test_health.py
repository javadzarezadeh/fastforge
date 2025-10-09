import os

os.environ["TESTING"] = "True"

import sys

from fastapi.testclient import TestClient

sys.path.append(os.path.join(os.path.dirname(__file__), ".."))

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
