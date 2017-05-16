from flask import Blueprint, session
from sqlalchemy.orm.exc import NoResultFound

from . import backend
from .api_utils import json_error, requires_json_auth, write_json
from .models import Entry, db

api_v2 = Blueprint("api_v2", __name__)


def decrypt_entries_pool(entry_key_pair):
    entry, key = entry_key_pair
    if entry.version == 4:
        return entry.to_json()
    else:
        return backend._decrypt_row(entry, key)


def __decrypt_multiprocess(enc_entries, master_key):
    from multiprocessing import Pool
    pool = Pool(5)
    entry_key_pairs = [(entry, master_key) for entry in enc_entries]
    results = pool.map(decrypt_entries_pool, entry_key_pairs)
    pool.close()
    pool.join()
    return results


@api_v2.route("/api/v2/entries", methods=["GET"])
@requires_json_auth
def api_get_entries():
    enc_entries = backend.get_entries(db.session, session["user_id"])
    dec_entries = __decrypt_multiprocess(enc_entries, session["password"])
    return write_json(200, dec_entries)


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
