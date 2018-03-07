from multiprocessing import Pool

from flask import Blueprint, session
from sqlalchemy.orm.exc import NoResultFound
from typing import List

from . import backend
from .api_utils import json_error, requires_json_auth, write_json
from .models import Entry, db

api_v2 = Blueprint("api_v2", __name__)


def jsonify_entries_pool(entry: Entry) -> dict:
    assert entry.version >= 4
    out = entry.to_json()
    # remove the encrypted elements in order to conserve bandwidth
    out.pop("username")
    out.pop("password")
    out.pop("extra")
    return out


def __jsonify_entries_multiprocess(enc_entries: List[Entry]):
    pool = Pool(5)
    results = pool.map(jsonify_entries_pool, enc_entries)
    pool.close()
    pool.join()
    return results


@api_v2.route("/api/v2/entries", methods=["GET"])
@requires_json_auth
def api_get_entries():
    """Return a list of encrypted entries.

    Arguments
    ---------
    none

    Response
    --------
    on success::

        [ entry-1, entry-2, ..., entry-n ]

    exactly what information is returned depends on the entry version

    on error::

    { "status": "error", "msg": string }

    Status codes
    ------------
    - 200: success
    - 500: there are some old entries (version < 4) so this method cannot work
    """
    enc_entries = backend.get_entries(db.session, session["user_id"])
    if any([entry.version < 4 for entry in enc_entries]):
        code, data = json_error(500, "This method does not work if there are entries below version 4")
        return write_json(code, data)
    jsonified_entries = __jsonify_entries_multiprocess(enc_entries)
    return write_json(200, jsonified_entries)


@api_v2.route("/api/v2/entries/<int:entry_id>", methods=["GET"])
@requires_json_auth
def api_get_entry(entry_id: int):
    """Decrypt the given entry and return the contents

    Arguments
    ---------

    Response
    --------
    on success::

        entry

    Exactly what information is returned depends on the entry version

    on error::

        { "status": "error", "msg": string }

    Status codes
    ------------
    - 200: success
    - 500: there are some old entries (version < 4) so this method cannot work
    """
    code = 200
    try:
        entry = db.session.query(Entry)\
            .filter_by(id=entry_id, user_id=session["user_id"], pinned=False)\
            .one()
        data = backend._decrypt_row(entry, session["password"])
    except NoResultFound:
        code, data = json_error(400, "no such entry or the entry does not belong to you")
    return write_json(code, data)
