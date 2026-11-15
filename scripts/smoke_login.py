"""Manual end-to-end check against the running server (https://127.0.0.1:5000).

Run: python scripts/smoke_login.py analyst1
Asks for the password and the current 6-digit code, then: CSRF -> login -> MFA -> /me ->
tries the admin user list (expect 403 unless the user is an admin) -> logout -> /me (expect 401).
The certificate is verified against certs/cert.pem, not ignored.
"""
import getpass
import http.cookiejar
import json
import ssl
import sys
import urllib.error
import urllib.request
from pathlib import Path

# 127.0.0.1, not "localhost": on Windows "localhost" tries IPv6 first and adds ~2 s per request
BASE = "https://127.0.0.1:5000/api"
CERT = Path(__file__).resolve().parent.parent / "certs" / "cert.pem"


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    username = sys.argv[1]
    ctx = ssl.create_default_context(cafile=str(CERT))
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()),
                                         urllib.request.HTTPSHandler(context=ctx))

    def call(method, path, body=None, token=None):
        req = urllib.request.Request(BASE + path, method=method,
                                     data=json.dumps(body).encode() if body is not None else None,
                                     headers={"Content-Type": "application/json", "X-CSRFToken": token or ""})
        try:
            with opener.open(req) as resp:
                status, data = resp.status, json.loads(resp.read() or b"{}")
        except urllib.error.HTTPError as err:
            status, data = err.code, json.loads(err.read() or b"{}")
        print(f"{method:5} {path:<16} -> {status} {data}")
        return status, data

    _, data = call("GET", "/auth/csrf")
    password = getpass.getpass(f"Password for {username}: ")
    status, data = call("POST", "/auth/login", {"username": username, "password": password}, data["csrf_token"])
    if status != 200:
        return 1
    code = input("6-digit code from your authenticator app: ")
    status, data = call("POST", "/auth/mfa", {"code": code}, data["csrf_token"])
    if status != 200:
        return 1
    token = data["csrf_token"]
    call("GET", "/auth/me")
    call("GET", "/admin/users")
    call("POST", "/auth/logout", {}, token)
    call("GET", "/auth/me")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
