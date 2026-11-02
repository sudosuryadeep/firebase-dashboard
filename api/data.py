
import os
import json
import hmac
import urllib.request
import urllib.error

from http.server import BaseHTTPRequestHandler
from urllib.parse import quote


BLOCKED = {
    "messages", "sms", "otp", "commands",
    "actions", "bombs", "passwords", "tokens"
}


def authorized(req):
    header = req.headers.get("Authorization", "")

    try:
        scheme, password = header.split(" ", 1)

        return (
            scheme.lower() == "bearer"
            and hmac.compare_digest(
                password,
                os.environ["DASHBOARD_PASSWORD"]
            )
        )
    except Exception:
        return False


def get_data():
    base_url = os.environ["FIREBASE_DATABASE_URL"].rstrip("/")
    path = os.environ.get(
        "FIREBASE_DATA_PATH", "public_dashboard"
    ).strip("/")

    if not path or any(
        part.lower() in BLOCKED
        for part in path.split("/")
    ):
        raise ValueError("Invalid data path")

    url = f"{base_url}/{quote(path, safe='/')}.json"

    request = urllib.request.Request(
        url,
        headers={"Accept": "application/json"}
    )

    with urllib.request.urlopen(request, timeout=10) as response:
        return json.loads(response.read().decode("utf-8"))


class handler(BaseHTTPRequestHandler):

    def send_json(self, status, payload):
        body = json.dumps(payload).encode()

        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path != "/api/data":
            self.send_json(404, {"error": "Not found"})
            return

        if not authorized(self):
            self.send_json(401, {"error": "Unauthorized"})
            return

        try:
            data = get_data()

            self.send_json(200, {
                "success": True,
                "data": data
            })

        except urllib.error.HTTPError as error:
            self.send_json(error.code, {
                "success": False,
                "error": "Firebase access denied or unavailable"
            })

        except Exception:
            self.send_json(500, {
                "success": False,
                "error": "Could not load Firebase data"
            })
