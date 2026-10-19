import os
import re
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app  # noqa: E402
from db import get_db  # noqa: E402
from manage import add_user  # noqa: E402

PASSWORD = "Test12345"


@pytest.fixture()
def app(tmp_path):
    app = create_app({
        "TESTING": True,
        "DATABASE": str(tmp_path / "test.db"),
        "SECRET_KEY": "test-secret",
        "PBKDF2_ITERATIONS": 1000,
    })
    for username, role in [("admin", "admin"), ("doc", "doctor"),
                           ("nurse", "nurse"), ("recep", "reception")]:
        add_user(app, username, f"User {username}", role, PASSWORD)
    return app


@pytest.fixture()
def client(app):
    return app.test_client()


def get_csrf(client, path="/login"):
    html = client.get(path).get_data(as_text=True)
    m = re.search(r'name="csrf_token" value="([^"]+)"', html)
    assert m, "csrf token not found"
    return m.group(1)


def login(client, username, password=PASSWORD):
    token = get_csrf(client)
    return client.post("/login", data={"username": username, "password": password,
                                       "csrf_token": token})


def post(client, url, data=None, token_path="/"):
    data = dict(data or {})
    data["csrf_token"] = get_csrf(client, token_path)
    return client.post(url, data=data)


PATIENT = {
    "full_name": "محمد أحمد",
    "dob": "1990-05-20",
    "gender": "male",
    "phone": "0791112233",
    "address": "عمّان",
    "blood_type": "O+",
    "allergies": "",
    "chronic_conditions": "",
    "emergency_contact": "",
    "national_id": "9905201234",
}


@pytest.fixture()
def make_patient(client):
    def _make(**overrides):
        data = dict(PATIENT)
        data.update(overrides)
        return post(client, "/patients/new", data, "/patients/new")
    return _make


@pytest.fixture()
def db_of(app):
    def _db():
        ctx = app.app_context()
        ctx.push()
        return get_db(), ctx
    return _db
