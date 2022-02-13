from .shared import db

from sqlalchemy import UniqueConstraint


class ApiStats(db.Model):
    __tablename__ = "api_stats"

    id = db.Column(db.Integer, db.Sequence("api_stats_id_seq"), primary_key=True)
    # the day in format yyyy-mm-dd
    day = db.Column(db.String, nullable=False)
    # the path being requested
    path = db.Column(db.String, nullable=False)
    # how many times that API has been hit
    count = db.Column(db.Integer, nullable=False, default=0, server_default='0')

    UniqueConstraint("day", "path", name="api_stats_unique_day_and_path")
