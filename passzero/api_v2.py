from datetime import datetime
from multiprocessing import Pool
from typing import List

from flask import Blueprint, session, escape
from sqlalchemy.orm.exc import NoResultFound

from . import backend
from .api_utils import (json_error, json_success, requires_json_auth,
                        requires_json_form_validation, write_json)
from .api_v1 import UserNotActiveException
from .forms import LoginFormV2
from .models import Entry, User, db

api_v2 = Blueprint("api_v2", __name__)


def jsonify_entries_pool(entry: Entry) -> dict:
    assert entry.version >= 4
    out = entry.to_json()
    # remove the encrypted elements in order to conserve bandwidth
    del out["username"]
    del out["password"]
    del out["extra"]
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
        data = entry.decrypt(session["password"])
    except NoResultFound:
        code, data = json_error(400, "no such entry or the entry does not belong to you")
    return write_json(code, data)


@api_v2.route("/api/v2/login", methods=["POST"])
@requires_json_form_validation(LoginFormV2)
def api_v1_login(request_data):
    """Login. On success, update session cookie.

    Arguments
    ---------
    - username_or_email: string (required)
    - password: string (required)

    Response
    --------
    Success or error message::

        { "status": "success"|"error", "msg": string }

    Status codes
    ------------
    - 200: success
    - 400: failed to validate arguments
    - 401: bad username-password combo or account doesn't exist or account isn't activated
    """
    try:
        # is the request data a username or email?
        # simple check here - @-sign means it's an email
        # since @-signs are not allowed in usernames
        is_email = "@" in request_data["username_or_email"]
        auth_field = ("email" if is_email else "username")
        if is_email:
            user = backend.get_account_with_email(db.session, request_data["username_or_email"])
        else:
            user = db.session.query(User).filter_by(username=request_data["username_or_email"]).one()

        if not user.active:
            raise UserNotActiveException
        if user.authenticate(request_data["password"]):
            session["email"] = user.email
            session["password"] = request_data["password"]
            session["user_id"] = user.id
            # write into last_login
            user.last_login = datetime.utcnow()
            db.session.add(user)
            db.session.commit()
            # craft message to return to user
            msg = "successfully logged in as {email}".format(
                email=escape(session["email"])
            )
            code, data = json_success(msg)
        else:
            code, data = json_error(401, f"Either the {auth_field} or password is incorrect")
    except NoResultFound:
        code, data = json_error(401, f"There is no account with that {auth_field}")
    except UserNotActiveException:
        code, data = json_error(
            401,
            "The account has not been activated. Check your email!"
        )
    return write_json(code, data)
