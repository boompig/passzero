from flask import Blueprint, session
from sqlalchemy.orm.exc import NoResultFound

from . import backend
from .api_utils import json_error, requires_json_auth, write_json
from .models import Entry, db

api_v2 = Blueprint("api_v2", __name__)

@api_v2.route("/api/v2/entries", methods=["GET"])
@requires_json_auth
def api_get_entries():
    entries = db.session.query(Entry)\
        .filter_by(user_id=session["user_id"], pinned=False)\
        .all()
    l = [entry.to_json() for entry in entries]
    return write_json(200, l)


@api_v2.route("/api/v2/entries/<int:entry_id>", methods=["GET"])
@requires_json_auth
def api_get_entry(entry_id):
    code = 200
    try:
        entry = db.session.query(Entry)\
            .filter_by(id=entry_id, user_id=session["user_id"], pinned=False)\
            .one()
        data = backend._decrypt_row(entry, session["password"])
    except NoResultFound:
        code, data = json_error(400, "no such entry or the entry does not belong to you")
    return write_json(code, data)
