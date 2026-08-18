"""Local web server for the Bioreactor login page.
Run from this folder with: py app.py
Then open: http://localhost:8000
"""

from __future__ import annotations

from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import hmac
import json
from pathlib import Path
import secrets
import sqlite3
from threading import Lock
from urllib.parse import urlparse
from flask import Flask
import os

    
BASE_DIR = Path(__file__).resolve().parent
DATABASE_PATH = BASE_DIR / "login.db"
SESSIONS: set[str] = set()
SESSIONS_LOCK = Lock()

STATIC_FILES = {
    "/": ("bioreactor.html", "text/html; charset=utf-8"),
    "/bioreactor.html": ("bioreactor.html", "text/html; charset=utf-8"),
    "/welcome.html": ("welcome.html", "text/html; charset=utf-8"),
    "/bioreactor.css": ("bioreactor.css", "text/css; charset=utf-8"),
    "/welcome.css": ("welcome.css", "text/css; charset=utf-8"),
    "/bioreactor.js": ("bioreactor.js", "application/javascript; charset=utf-8"),
    "/rq4_global_hawk.glb": ("rq4_global_hawk.glb", "model/gltf-binary"),
}


def get_session_token(request: BaseHTTPRequestHandler) -> str | None:
    cookies = SimpleCookie()
    cookies.load(request.headers.get("Cookie", ""))
    morsel = cookies.get("bioreactor_session")
    return morsel.value if morsel else None


def is_authenticated(request: BaseHTTPRequestHandler) -> bool:
    token = get_session_token(request)
    if not token:
        return False
    with SESSIONS_LOCK:
        return token in SESSIONS


class BioreactorRequestHandler(BaseHTTPRequestHandler):
    def send_json(self, status: HTTPStatus, content: dict, cookie: str | None = None) -> None:
        payload = json.dumps(content).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
        self.wfile.write(payload)

    def read_json_body(self) -> dict:
        content_length = int(self.headers.get("Content-Length", "0"))
        if content_length <= 0 or content_length > 4096:
            raise ValueError("Invalid request size.")
        return json.loads(self.rfile.read(content_length).decode("utf-8"))

    def do_GET(self) -> None:
        path = urlparse(self.path).path

        if path == "/welcome.html" and not is_authenticated(self):
            self.send_response(HTTPStatus.SEE_OTHER)
            self.send_header("Location", "/")
            self.end_headers()
            return

        page = STATIC_FILES.get(path)
        if not page:
            self.send_error(HTTPStatus.NOT_FOUND, "File not found")
            return

        file_path = BASE_DIR / page[0]
        try:
            content = file_path.read_bytes()
        except FileNotFoundError:
            self.send_error(HTTPStatus.NOT_FOUND, "File not found")
            return

        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", page[1])
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        if path == "/api/login":
            self.handle_login()
        elif path == "/api/logout":
            self.handle_logout()
        else:
            self.send_error(HTTPStatus.NOT_FOUND, "Endpoint not found")

    def handle_login(self) -> None:
        try:
            credentials = self.read_json_body()
            username = credentials.get("username", "")
            password = credentials.get("password", "")
        except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
            self.send_json(HTTPStatus.BAD_REQUEST, {"success": False, "message": "Invalid login request."})
            return

        if not isinstance(username, str) or not isinstance(password, str):
            self.send_json(HTTPStatus.BAD_REQUEST, {"success": False, "message": "Invalid login request."})
            return

        username = username.strip()
        if not username or not password:
            invalid_fields = []
            if not username:
                invalid_fields.append("username")
            if not password:
                invalid_fields.append("password")
            self.send_json(
                HTTPStatus.BAD_REQUEST,
                {"success": False, "message": "Enter both your username and password.", "invalid_fields": invalid_fields},
            )
            return

        try:
            with sqlite3.connect(DATABASE_PATH) as connection:
                user = connection.execute(
                    "SELECT password FROM login_page WHERE username = ?", (username,)
                ).fetchone()
                password_exists = connection.execute(
                    "SELECT 1 FROM login_page WHERE password = ? LIMIT 1", (password,)
                ).fetchone() is not None
        except sqlite3.Error:
            self.send_json(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                {"success": False, "message": "The login database is unavailable."},
            )
            return

        if user and hmac.compare_digest(user[0], password):
            token = secrets.token_urlsafe(32)
            with SESSIONS_LOCK:
                SESSIONS.add(token)
            self.send_json(
                HTTPStatus.OK,
                {"success": True},
                f"bioreactor_session={token}; HttpOnly; SameSite=Lax; Path=/",
            )
        elif user:
            self.send_json(
                HTTPStatus.UNAUTHORIZED,
                {"success": False, "message": "Invalid password.", "invalid_fields": ["password"]},
            )
        elif password_exists:
            self.send_json(
                HTTPStatus.UNAUTHORIZED,
                {"success": False, "message": "Invalid username.", "invalid_fields": ["username"]},
            )
        else:
            self.send_json(
                HTTPStatus.UNAUTHORIZED,
                {
                    "success": False,
                    "message": "Invalid username and password.",
                    "invalid_fields": ["username", "password"],
                },
            )

    def handle_logout(self) -> None:
        token = get_session_token(self)
        if token:
            with SESSIONS_LOCK:
                SESSIONS.discard(token)

        self.send_json(
            HTTPStatus.OK,
            {"success": True},
            "bioreactor_session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0",
        )

    def log_message(self, format: str, *args: object) -> None:
        """Keep the console output focused on the server start message."""


if __name__ == "__main__":
    if not DATABASE_PATH.exists():
        raise FileNotFoundError(f"Database not found: {DATABASE_PATH}")


    port = int(os.environ.get("PORT", 8000))

    server = ThreadingHTTPServer(("0.0.0.0", port), BioreactorRequestHandler)
    print("Bioreactor login is running at http://localhost:8000")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nServer stopped.")
    finally:
        server.server_close()
