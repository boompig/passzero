from .shared import db

from sqlalchemy import UniqueConstraint


class ApiStats(db.Model):
    __tablename__ = "api_stats"

    id = db.Column(db.Integer, db.Sequence("api_stats_id_seq"), primary_key=True)
    # the day in format yyyy-mm-dd
    # NOTE: since we were recording too many stats, moving to a once-per-week model
    # therefore the day will actually be the first Monday of each week moving forward
    day = db.Column(db.String, nullable=False)
    # this will be a 0-based number referring to the week of the year
    week_of_year = db.Column(db.Integer)
    # the path being requested
    path = db.Column(db.String, nullable=False)
    # how many times that API has been hit
    count = db.Column(db.Integer, nullable=False, default=0, server_default='0')

    UniqueConstraint("day", "path", name="api_stats_unique_day_and_path")
