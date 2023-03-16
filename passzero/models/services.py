from passzero.models.shared import db


class Service(db.Model):
    __tablename__ = "services"
    name = db.Column(db.String, primary_key=True, nullable=False)
    link = db.Column(db.String)
    has_two_factor = db.Column(db.Boolean)

    def to_json(self) -> dict:
        return {
            "name": self.name,
            "link": self.link,
            "has_two_factor": self.has_two_factor,
        }
