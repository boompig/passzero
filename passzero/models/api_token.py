from datetime import datetime

from passzero.models.shared import db


class ApiToken(db.Model):
    __tablename__ = "api_tokens"
    id = db.Column(db.Integer, db.Sequence("api_token_id_seq"), primary_key=True)
    # for now there can be at most one API token per user
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, unique=True)

    # the actual token substance
    token = db.Column(db.String, nullable=False)
    # JTI (quick way to check uniqueness)
    token_identity = db.Column(db.String, nullable=False)

    issue_time = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    expire_time = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def is_expired(self) -> bool:
        return self.expire_time < datetime.utcnow()
