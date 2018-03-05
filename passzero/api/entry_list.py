from multiprocessing import Pool

from flask_jwt_extended import get_jwt_identity, jwt_required
from flask_restplus import Resource, reqparse
from typing import List

from .. import backend
from ..api_utils import json_error_v2, json_success_v2
from ..models import Entry, User, db


def jsonify_entries_pool(entry: Entry) -> dict:
    assert entry.version >= 4
    out = entry.to_json()
    # remove the encrypted elements in order to conserve bandwidth
    out.pop("username")
    out.pop("password")
    out.pop("extra")
    return out


def _jsonify_entries_multiprocess(enc_entries: List[Entry]):
    pool = Pool(5)
    results = pool.map(jsonify_entries_pool, enc_entries)
    pool.close()
    pool.join()
    return results


def _jsonify_entries_single_thread(enc_entries: List[Entry]):
    return [jsonify_entries_pool(entry) for entry in enc_entries]


def jsonify_entries(enc_entries: List[Entry]):
    return _jsonify_entries_single_thread(enc_entries)


class ApiEntryList(Resource):

    @jwt_required
    def post(self):
        """Create a new entry for the logged-in user.

        Arguments
        ---------
        - entry: dict (required)
            - account: string (required)
            - username: string (required)
            - password: string(required)
            - extra: string (optional)
            - has_2fa: boolean (required)
        - password: string (required)

        Response
        --------
        on success::

            { "entry_id": number }

        on error::

            { "status": "error", "msg": string }

        Status codes
        ------------
        - 200: success
        - 400: various input validation errors
        - 401: not authenticated / password is not correct
        """
        parser = reqparse.RequestParser()
        parser.add_argument("entry", type=dict, required=True)
        parser.add_argument("password", type=str, required=True)
        args = parser.parse_args()

        entry_parser = reqparse.RequestParser()
        entry_parser.add_argument("account", type=str, required=True, location=("entry", ))
        entry_parser.add_argument("username", type=str, required=True, location=("entry", ))
        entry_parser.add_argument("password", type=str, required=True, location=("entry", ))
        entry_parser.add_argument("extra", required=False, type=str, default="", location=("entry", ))
        entry_parser.add_argument("has_2fa", required=False, type=bool, default=False, location=("entry", ))
        entry_parser.parse_args(req=args)
        user_id = get_jwt_identity()["user_id"]
        user = db.session.query(User).filter_by(id=user_id).one()
        if user.authenticate(args.password):
            entry = backend.insert_entry_for_user(
                db_session=db.session,
                dec_entry=args.entry,
                user_id=user_id,
                user_key=args.password
            )
            return { "entry_id": entry.id }
        else:
            return json_error_v2("Password is not correct", 401)

    @jwt_required
    def delete(self):
        """Delete *all* entries for the logged-in user.

        Arguments
        ---------
        none

        Response
        --------
        Success or error message::

            { "status": "success"|"error", "msg": string }

        Status codes
        ------------
        - 200: success
        - 401: not authenticated
        """
        identity = get_jwt_identity()
        user = db.session.query(User).filter_by(id=identity["user_id"]).one()
        backend.delete_all_entries(db.session, user)
        return json_success_v2("Deleted all entries")

    @jwt_required
    def get(self):
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
        user_id = get_jwt_identity()["user_id"]
        enc_entries = backend.get_entries(db.session, user_id)
        if any([entry.version < 4 for entry in enc_entries]):
            return json_error_v2("This method does not work if there are entries below version 4", 500)
        return jsonify_entries(enc_entries)

