import time
from typing import List

from flask import current_app, make_response
from flask_jwt_extended import get_jwt_identity, jwt_required
from flask_restx import Namespace, Resource, reqparse

from passzero import backend, export_utils
from passzero.api import app_error_codes
from passzero.api.jwt_auth import authorizations
from passzero.api_utils import json_error_v2, json_success_v2
from passzero.models import Entry, User, db


def jsonify_entries(enc_entries: List[Entry]):
    return [entry.to_json() for entry in enc_entries]


ns = Namespace("EntryList", authorizations=authorizations)


@ns.route("")
class ApiEntryList(Resource):

    @ns.doc(security="apikey")
    @jwt_required()
    def post(self):
        """Create a new entry for the logged-in user.

        Authentication
        --------------
        JWT

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
        entry_parser.add_argument("has_2fa", required=True, type=bool, location=("entry", ))
        entry_parser.parse_args(req=args)
        user_id = get_jwt_identity()["user_id"]
        user = db.session.query(User).filter_by(id=user_id).one()
        if user.authenticate(args.password):
            try:
                entry = backend.insert_entry_for_user(
                    db_session=db.session,
                    dec_entry=args.entry,
                    user_id=user_id,
                    user_key=args.password
                )
                return {"entry_id": entry.id}
            except backend.EntryValidationError as err:
                return json_error_v2(f"Failed to validate entry: {err}", 400)
        else:
            return json_error_v2("Password is not correct", 401)

    @ns.doc(security="apikey")
    @jwt_required()
    def delete(self):
        """Delete *all* entries for the logged-in user.

        Authentication
        --------------
        JWT

        Arguments
        ---------
        - password: str (required)

        Response
        --------
        Success or error message::

            { "status": "success"|"error", "msg": string }

        Status codes
        ------------
        - 200: success
        - 400: parameter validation error
        - 401: not authenticated / password is not correct
        """
        parser = reqparse.RequestParser()
        parser.add_argument("password", type=str, required=True)
        args = parser.parse_args()
        identity = get_jwt_identity()
        user = db.session.query(User).filter_by(id=identity["user_id"]).one()
        if user.authenticate(args.password):
            backend.delete_all_entries(db.session, user, args.password)
            return json_success_v2("Deleted all entries")
        else:
            return json_error_v2("Password is not correct", 401)

    @ns.doc(security="apikey")
    @jwt_required()
    def get(self):
        """Return a list of encrypted entries.

        Authentication
        --------------
        JWT

        Arguments
        ---------
        none

        Response
        --------
        on success::

            [ entry-1, entry-2, ..., entry-n ]

        exactly what information is returned depends on the entry version

        on error::

            { "status": "error", "msg": string, "code": int }

        Status codes
        ------------
        - 200: success
        - 500: there are some old entries (version < 4) so this method cannot work
        """
        user_id = get_jwt_identity()["user_id"]
        start = time.time()
        enc_entries = backend.get_entries(db.session, user_id)
        end = time.time()
        current_app.logger.info("Took %.3f seconds to retrieve %d encrypted entries from database",
                                end - start, len(enc_entries))
        if any([entry.version < 4 for entry in enc_entries]):
            return json_error_v2("This method does not work if there are entries below version 4",
                                 http_status_code=500,
                                 app_error_code=app_error_codes.ENTRIES_TOO_OLD)
        start = time.time()
        rval = jsonify_entries(enc_entries)
        end = time.time()
        current_app.logger.info("Took %.3f seconds to JSON-ify %d encrypted entries",
                                end - start, len(enc_entries))
        return rval

    @ns.doc(security="apikey")
    @jwt_required()
    def patch(self):
        """
        Update the versions of all the entries to the latest version.
        This could take a long time.

        Authentication
        --------------
        JWT

        Arguments
        ---------
        - password: string (required)
        - limit: number (optional)

        Response
        --------
        on success::

            { "status": "success", "num_updated": int }

        on error::

            { "status": "error", "msg": string }


        Status codes
        ------------
        - 200: success
        - 400: various input validation errors
        - 401: not authenticated / password is not correct
        """
        parser = reqparse.RequestParser()
        parser.add_argument("password", type=str, required=True)
        parser.add_argument("limit", type=int, required=False)
        args = parser.parse_args()
        user_id = get_jwt_identity()["user_id"]
        user = db.session.query(User).filter_by(id=user_id).one()
        if user.authenticate(args.password):
            num_updated = backend.update_entry_versions_for_user(
                db_session=db.session,
                user_id=user_id,
                master_key=args.password,
                limit=(args.limit if args.limit else None)
            )
            return {
                "num_updated": num_updated
            }
        else:
            return json_error_v2("Password is not correct", 401)


@ns.route("/export")
class Export(Resource):
    @ns.doc(security="apikey")
    @jwt_required()
    def post(self):
        """
        Export the entry list into a CSV file.

        Authentication
        --------------
        JWT

        Arguments
        ---------
        - password: string (required)

        Response
        --------
        on success::

            a CSV file

        exactly what information is returned depends on the entry version

        on error::

            { "status": "error", "msg": string, "code": int }

        Status codes
        ------------
        - 200: success
        - 401: incorrect master password
        """
        parser = reqparse.RequestParser()
        parser.add_argument("password", type=str, required=True)
        args = parser.parse_args()

        user_id = get_jwt_identity()["user_id"]
        user = db.session.query(User).filter_by(id=user_id).one()  # type: User
        if user.authenticate(args.password):
            start = time.time()
            export_contents = export_utils.export_decrypted_entries(
                db.session,
                user_id=user_id,
                master_password=args.password,
            )
            response = make_response(export_contents)
            response.headers["Content-Disposition"] = (
                "attachment; filename=%s" % current_app.config['DUMP_FILE']
            )
            end = time.time()
            current_app.logger.info("Took %.3f seconds to complete password score evaluation", end - start)

            return response
        else:
            return json_error_v2("Failed to authenticate with provided password", 401)


@ns.route("/password-strength")
class PasswordStrength(Resource):
    @ns.doc(security="apikey")
    @jwt_required()
    def get(self):
        """Return a list of decrypted entries and their relative strengths.

        Authentication
        --------------
        JWT

        Arguments
        ---------
        - password: string (required)

        Response
        --------
        on success::

            [ dec-entry-scores-1, dec-entry-scores-2, ..., dec-entry-scores-n ]

        exactly what information is returned depends on the entry version

        on error::

            { "status": "error", "msg": string, "code": int }

        Status codes
        ------------
        - 200: success
        - 401: incorrect master password
        """
        parser = reqparse.RequestParser()
        parser.add_argument("password", type=str, required=True)
        args = parser.parse_args()

        user_id = get_jwt_identity()["user_id"]
        # guaranteed to exist
        user = db.session.query(User).filter_by(id=user_id).one()  # type: User
        if user.authenticate(args.password):
            start = time.time()
            entries = backend.get_entries(db.session, user_id)
            dec_entries = backend.decrypt_entries(entries, args.password)
            entry_scores = backend.password_strength_scores(user.email, dec_entries)
            end = time.time()
            current_app.logger.info("Took %.3f seconds to complete password score evaluation", end - start)
            return entry_scores
        else:
            return json_error_v2("Failed to authenticate with provided password", 401)


@ns.route("/two-factor-audit")
class TwoFactorAudit(Resource):

    @ns.doc(security="apikey")
    @jwt_required()
    def get(self):
        """Return a list of decrypted entries and their relative strengths.

        Authentication
        --------------
        JWT

        Arguments
        ---------
        none

        Response
        --------
        on success::

        A map from entries' account names to their audit info.
        Each entry will look like this:

            { "service_has_2fa": bool, "entry_has_2fa": bool, "entry_id": int }

        on error::

            { "status": "error", "msg": string, "code": int }

        Status codes
        ------------
        - 200: success
        """
        user_id = get_jwt_identity()["user_id"]
        two_factor_map = backend.two_factor_audit(db.session, user_id)
        return two_factor_map
