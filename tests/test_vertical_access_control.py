import sqlite3

import pytest
from werkzeug.security import generate_password_hash

import app as app_module

flask_app = app_module.app


@pytest.fixture
def client(tmp_path, monkeypatch):
    #Will create a temporary database for the test
    test_db = tmp_path / "test_expenses.db"
    monkeypatch.setattr(app_module, "DB", str(test_db))

    connection = sqlite3.connect(test_db)

    connection.executescript("""
        CREATE TABLE users (
            id INTEGER PRIMARY KEY,
            username TEXT,
            password TEXT,
            name TEXT,
            role TEXT
            );

        CREATE TABLE claims (
            id INTEGER PRIMARY KEY,
            user_id INTEGER,
            merchant TEXT,
            amount REAL,
            note TEXT,
            status TEXT
            );

    """)

    users = [
        ("jdoe", "password1", "Jane Doe", "staff"),
        ("rsmith", "letmein", "Rob Smith", "staff"),
        ("achen", "Summer2026", "Ada Chen", "finance"),
        ("admin", "admin", "System Admin", "admin")]

    for username, password, name, role in users:
        password_hash = generate_password_hash(password)
        connection.execute(
            "INSERT INTO users VALUES (?, ?, ?, ?, ?)",
            (None, username, password_hash, name, role)
        )


    connection.commit()
    connection.close()

    flask_app.config["TESTING"] = True

    with flask_app.test_client() as test_client:
        yield test_client

USERS = {
    "jane": {"username": "jdoe", "password": "password1"},
    "rob": {"username": "rsmith", "password": "letmein"},
    "admin": {"username": "admin", "password": "admin"},
}

def login(client, user):
    response = client.post(
        "/login",
        data=USERS[user],
        follow_redirects=True
    )
    assert response.status_code == 200

# CWE-862: Missing Authorization
# CWE-863: Incorrect Authorization
# OWASP WSTG-ATHZ-02: Testing for Bypassing Authorization Schema

@pytest.mark.parametrize(
    "user, expected_status",
    [
        ("jane", 403),
        ("rob", 403),
        ("admin", 200),
    ]
)
def test_vertical_access_control(client, user, expected_status):
    login(client, user)

    response = client.get("/admin/users")

    assert response.status_code == expected_status

    if user in ("jane", "rob"):
        assert b"System Admin" not in response.data

    if user == "admin":
        assert b"System Admin" in response.data

def test_anonymous_user_cannot_access_admin_users(client):
    response = client.get("/admin/users")
    assert response.status_code == 302

