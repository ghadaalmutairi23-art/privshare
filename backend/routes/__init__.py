"""API blueprints."""
from flask import abort, request


def json_body() -> dict:
    """Parsed JSON object from the request, or 400."""
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        abort(400)
    return body
