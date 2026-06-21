from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class ScanHistory(db.Model):
    __tablename__ = "scan_history"

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    analysis_id = db.Column(
        db.String(64),
        unique=True,
        index=True
    )

    filename = db.Column(
        db.String(255),
        index=True
    )

    sender = db.Column(
        db.String(255),
        index=True
    )

    subject = db.Column(
        db.String(500)
    )

    domain = db.Column(
        db.String(255),
        index=True
    )

    ioc_count = db.Column(
        db.Integer,
        default=0
    )

    confidence = db.Column(
        db.Integer,
        default=0
    )

    analysis_status = db.Column(
        db.String(50),
        index=True
    )

    risk = db.Column(
        db.String(20),
        index=True
    )

    threat_score = db.Column(
        db.Integer
    )

    mitre_techniques = db.Column(
        db.Text
    )

    report_path = db.Column(
        db.String(500)
    )

    timestamp = db.Column(
        db.DateTime,
        server_default=db.func.now(),
        index=True
    )
