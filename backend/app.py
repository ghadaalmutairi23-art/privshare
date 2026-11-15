"""Flask application factory (JSON REST API only).

Run: python -m backend.app   ->  https://localhost:5000
"""
from contextlib import closing

from flask import Flask, jsonify
from werkzeug.exceptions import HTTPException

from . import chain, db, security
from .config import ROOT, load_config
from .routes import admin_routes, approval_routes, auth_routes, health_routes, owner_routes, query_routes

CERT_FILE = ROOT / "certs" / "cert.pem"
KEY_FILE = ROOT / "certs" / "key.pem"


def create_app(overrides: dict | None = None) -> Flask:
    app = Flask(__name__)
    app.config.update(load_config())
    if overrides:
        app.config.update(overrides)

    db.init_app(app)
    security.init_app(app)

    client = chain.create(app.config["CHAIN_BACKEND"])
    if isinstance(client, chain.StubChain):
        with closing(db.connect(app.config["DB_PATH"])) as conn:
            client.load_approvals(conn)
    app.extensions["chain"] = client

    app.register_blueprint(health_routes.bp, url_prefix="/api")
    app.register_blueprint(auth_routes.bp, url_prefix="/api/auth")
    app.register_blueprint(admin_routes.bp, url_prefix="/api/admin")
    app.register_blueprint(approval_routes.bp, url_prefix="/api/approvals")
    app.register_blueprint(query_routes.bp, url_prefix="/api/query")
    app.register_blueprint(owner_routes.bp, url_prefix="/api/owner")

    @app.errorhandler(HTTPException)
    def http_error(exc: HTTPException):
        return jsonify(error=exc.name), exc.code

    @app.errorhandler(Exception)
    def server_error(_exc: Exception):
        app.logger.exception("Unhandled error")  # stack trace in the server log only
        return jsonify(error="Internal server error"), 500

    return app


def main() -> None:
    if not (CERT_FILE.exists() and KEY_FILE.exists()):
        raise SystemExit("TLS certificate not found. Run: python scripts/make_cert.py")
    app = create_app()
    app.run(host="127.0.0.1", port=5000, ssl_context=(str(CERT_FILE), str(KEY_FILE)))


if __name__ == "__main__":
    main()
