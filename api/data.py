
import os
import json
import base64
import hmac

from http.server import BaseHTTPRequestHandler
from urllib.parse import urlparse

import firebase_admin
from firebase_admin import credentials, db


BLOCKED_KEYS = (
    "otp", "sms", "message", "command", "action",
    "bomb", "token", "password", "secret",
    "credential", "bank"
)


def clean_data(value):
    """Remove sensitive fields from displayed data."""

    if isinstance(value, dict):
        result = {}

        for key, item in value.items():
            if any(word in key.lower() for word in BLOCKED_KEYS):
                continue

            result[key] = clean_data(item)

        return result

    if isinstance(value, list):
        return [clean_data(item) for item in value]

    return value


def get_firebase_app():
    try:
        return firebase_admin.get_app("dashboard")

    except ValueError:
        account = json.loads(
            os.environ["FIREBASE_SERVICE_ACCOUNT_JSON"]
        )

        credential = credentials.Certificate(account)

        return firebase_admin.initialize_app(
            credential,
            {
                "databaseURL": os.environ[
                    "FIREBASE_DATABASE_URL"
                ]
            },
            name="dashboard"
        )


def authorized(request):
    header = request.headers.get("Authorization", "")

    try:
        scheme, encoded = header.split(" ", 1)

        if scheme.lower() != "basic":
            return False

        decoded = base64.b64decode(
            encoded,
            validate=True
        ).decode("utf-8")

        username, password = decoded.split(":", 1)

        expected_user = os.environ["DASHBOARD_USER"]
        expected_password = os.environ["DASHBOARD_PASSWORD"]

        return (
            hmac.compare_digest(username, expected_user)
            and hmac.compare_digest(password, expected_password)
        )

    except Exception:
        return False


class handler(BaseHTTPRequestHandler):

    def respond(self, status, payload):
        body = json.dumps(payload).encode("utf-8")

        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):

        if urlparse(self.path).path != "/api/data":
            self.respond(404, {"error": "Not found"})
            return

        if not authorized(self):
            self.send_response(401)
            self.send_header(
                "WWW-Authenticate",
                'Basic realm="Private Dashboard"'
            )
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        try:
            app = get_firebase_app()

            # Fixed path: no arbitrary root database dump.
            ref = db.reference(
                "public_dashboard",
                app=app
            )

            data = ref.get()

            self.respond(200, {
                "success": True,
                "data": clean_data(data)
            })

        except Exception:
            # Do not expose credentials or internal error details.
            self.respond(500, {
                "success": False,
                "error": "Firebase connection failed"
            })
