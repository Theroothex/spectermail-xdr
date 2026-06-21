import logging
import os
import secrets
from logging.handlers import RotatingFileHandler
from pathlib import Path

from flask import Flask, request
from werkzeug.middleware.proxy_fix import ProxyFix


BASE_DIR = Path(__file__).resolve().parent.parent


def _bool_env(name, default=False):
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _load_dotenv(path):
    if not path.exists():
        return

    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip("'\""))


def _configure_logging(app):
    log_dir = BASE_DIR / "logs"
    log_dir.mkdir(exist_ok=True)

    formatter = logging.Formatter(
        "%(asctime)s %(levelname)s %(name)s %(message)s"
    )

    for name, filename in {
        "spectermail.app": "application.log",
        "spectermail.security": "security.log",
        "spectermail.analysis": "analysis.log",
        "spectermail.audit": "audit.log",
    }.items():
        logger = logging.getLogger(name)
        logger.setLevel(logging.INFO)
        if not logger.handlers:
            handler = RotatingFileHandler(
                log_dir / filename,
                maxBytes=1_000_000,
                backupCount=5,
                encoding="utf-8",
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)

    app.logger.handlers.clear()
    app.logger.setLevel(logging.INFO)
    app.logger.addHandler(logging.getLogger("spectermail.app").handlers[0])


def _ensure_scan_history_schema(db):
    from sqlalchemy import inspect, text

    inspector = inspect(db.engine)
    if "scan_history" not in inspector.get_table_names():
        return

    existing = {
        column["name"]
        for column in inspector.get_columns("scan_history")
    }
    columns = {
        "filename": "VARCHAR(255)",
        "sender": "VARCHAR(255)",
        "subject": "VARCHAR(500)",
        "domain": "VARCHAR(255)",
        "ioc_count": "INTEGER DEFAULT 0",
        "confidence": "INTEGER DEFAULT 0",
        "analysis_status": "VARCHAR(50)",
        "risk": "VARCHAR(20)",
        "threat_score": "INTEGER DEFAULT 0",
        "mitre_techniques": "TEXT",
        "report_path": "VARCHAR(500)",
        "analysis_id": "VARCHAR(64)",
        "timestamp": "DATETIME",
    }

    with db.engine.begin() as connection:
        for name, ddl in columns.items():
            if name not in existing:
                connection.execute(
                    text(f"ALTER TABLE scan_history ADD COLUMN {name} {ddl}")
                )

        refreshed = {
            column["name"]
            for column in inspect(db.engine).get_columns("scan_history")
        }
        if "analysis_status" in refreshed:
            connection.execute(
                text(
                    "UPDATE scan_history "
                    "SET analysis_status = 'Completed' "
                    "WHERE analysis_status IS NULL OR analysis_status = ''"
                )
            )


def create_app():

    app = Flask(__name__)
    _load_dotenv(BASE_DIR / ".env")

    secret_key = os.getenv("SECRET_KEY")
    if not secret_key:
        secret_key = secrets.token_hex(32)
        logging.getLogger("spectermail.security").warning(
            "SECRET_KEY was not set; generated an ephemeral development key"
        )

    app.config["SECRET_KEY"] = secret_key
    app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv(
        "DATABASE_URL",
        "sqlite:///scan_history.db",
    )
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["MAX_CONTENT_LENGTH"] = int(
        os.getenv("MAX_CONTENT_LENGTH", str(2 * 1024 * 1024))
    )
    app.config["UPLOAD_EXTENSIONS"] = {".eml", ".txt"}
    app.config["UPLOAD_DIR"] = str(BASE_DIR / "instance" / "uploads")
    app.config["REPORT_DIR"] = str(BASE_DIR / "instance" / "reports")
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    app.config["SESSION_COOKIE_SECURE"] = _bool_env("SESSION_COOKIE_SECURE")
    app.config["DEBUG"] = _bool_env("FLASK_DEBUG")
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)
    _configure_logging(app)

    from app.models import db
    db.init_app(app)

    from app.routes.home_routes import home_bp
    app.register_blueprint(home_bp)

    from app.routes.report_routes import report_bp
    app.register_blueprint(report_bp)

    with app.app_context():
        db.create_all()
        _ensure_scan_history_schema(db)

    @app.context_processor
    def inject_security_helpers():
        from app.security import get_csrf_token

        return {"csrf_token": get_csrf_token}

    @app.after_request
    def set_security_headers(response):
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        response.headers.setdefault(
            "Permissions-Policy",
            "camera=(), microphone=(), geolocation=()",
        )
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; "
            "style-src 'self' 'unsafe-inline'; "
            "script-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
        )
        if request.is_secure:
            response.headers.setdefault(
                "Strict-Transport-Security",
                "max-age=31536000; includeSubDomains",
            )
        return response

    return app
