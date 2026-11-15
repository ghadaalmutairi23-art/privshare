"""Client for the university information system (SIS) API: pulls all students page by page.

HTTPS is verified against SIS_CA_FILE (our self-signed cert locally). The API key goes in
the X-API-Key header and is never logged.
"""
import json
import ssl
import urllib.error
import urllib.parse
import urllib.request

MAX_PAGES = 1000


class SISUnavailable(Exception):
    pass


def _get_page(base_url: str, api_key: str, page: int, ca_file: str | None, timeout: float) -> dict:
    url = f"{base_url.rstrip('/')}/api/students?{urllib.parse.urlencode({'page': page})}"
    req = urllib.request.Request(url, headers={"X-API-Key": api_key, "Accept": "application/json"})
    ctx = ssl.create_default_context(cafile=ca_file) if url.startswith("https") else None
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
        return json.loads(resp.read())


def fetch_all(base_url: str, api_key: str, ca_file: str | None = None, timeout: float = 10.0,
              get_page=None) -> list[dict]:
    """All students from the SIS. `get_page(page) -> dict` can be injected for tests."""
    if not base_url or not api_key:
        raise SISUnavailable("SIS_URL and SIS_API_KEY must be configured")
    get_page = get_page or (lambda p: _get_page(base_url, api_key, p, ca_file, timeout))
    students, page = [], 1
    try:
        while page <= MAX_PAGES:
            body = get_page(page)
            batch = body.get("students") if isinstance(body, dict) else None
            if not isinstance(batch, list):
                raise SISUnavailable("Unexpected response from the university system")
            students.extend(b for b in batch if isinstance(b, dict))
            if not batch or len(students) >= int(body.get("total", 0)):
                return students
            page += 1
    except urllib.error.HTTPError as exc:
        msg = "University system rejected the API key" if exc.code in (401, 403) else "University system error"
        raise SISUnavailable(msg) from exc
    except (urllib.error.URLError, OSError, ValueError) as exc:
        raise SISUnavailable("University system unreachable") from exc
    raise SISUnavailable("Too many pages from the university system")
