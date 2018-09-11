from .shared import db


class Tag(db.Model):
    """Each user can create any number of tags
    A tag has a name and an associated user.
    Tags are *not* encrypted in the database"""
    __tablename__ = "tags"
    id = db.Column(db.Integer, db.Sequence("tag_id_seq"), primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    name = db.Column(db.String, nullable=False)


class EntryTag(db.Model):
    """This table represents the association between entries and tags.
    These mappings are *not* encrypted in the database
    """
    __tablename__ = "entry_tags"
    id = db.Column(db.Integer, db.Sequence("entry_tag_id_seq"), primary_key=True)
    entry_id = db.Column(db.Integer, db.ForeignKey("entries.id"), nullable=False)
    tag_id = db.Column(db.Integer, db.ForeignKey("tags.id"), nullable=False)

    name = db.relationship(Tag,
        uselist=False,
    )
