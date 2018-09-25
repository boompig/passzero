from datetime import datetime

from passzero.config import TOKEN_SIZE
from passzero.crypto_utils import random_hex

from .shared import db


class AuthToken(db.Model):
    __tablename__ = "auth_tokens"
    id = db.Column(db.Integer, db.Sequence("entries_id_seq"), primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    token = db.Column(db.String, nullable=False)
    issue_time = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    # in seconds
    MAX_AGE = 15 * 60

    def random_token(self) -> None:
        self.token = random_hex(TOKEN_SIZE)

    def is_expired(self) -> bool:
        """
        :return:                True iff expired
        :rtype:                 bool
        """
        delta = datetime.utcnow() - self.issue_time
        return delta.seconds > self.MAX_AGE

    def __repr__(self):
        return "<AuthToken(user_id=%d, token=%s)>" % (self.user_id, self.token)
