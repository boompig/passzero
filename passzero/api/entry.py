from flask import escape
from flask_jwt_extended import get_jwt_identity, jwt_required
from sqlalchemy.orm.exc import NoResultFound

from flask_restx import Namespace, Resource, reqparse

from .. import backend
from ..api_utils import json_error_v2, json_success_v2
from ..models import Entry, User, db
from .jwt_auth import authorizations

ns = Namespace("Entry", authorizations=authorizations)


@ns.route("")
class ApiEntry(Resource):

    @ns.doc(security="apikey")
    @jwt_required
    def delete(self, entry_id: int):
        """Delete the entry with the given ID.

        Authentication
        --------------
        JWT

        Arguments
        ---------
        - password: string (required)

        Response
        --------
        Success or error message::

            { "status": "success"|"error", "msg": string }

        Status codes
        ------------
        - 200: success
        - 400: entry does not exist or does not belong to logged-in user, or parameter validation error
        - 401: not authenticated / password is not correct
        """
        parser = reqparse.RequestParser()
        parser.add_argument("password", type=str, required=True)
        args = parser.parse_args()
        user_id = get_jwt_identity()["user_id"]
        # guaranteed to exist
        user = db.session.query(User).filter_by(id=user_id).one()
        if user.authenticate(args.password):
            try:
                backend.delete_entry(db.session, entry_id, user_id, args.password)
                return json_success_v2("successfully deleted entry with ID %d" % entry_id)
            except NoResultFound:
                return json_error_v2("no such entry", 400)
            except AssertionError:
                return json_error_v2("the given entry does not belong to you", 400)
        else:
            return json_error_v2("Password is not correct", 401)

    @ns.doc(security="apikey")
    @jwt_required
    def patch(self, entry_id: int):
        """Update the specified entry.

        Authentication
        --------------
        JWT

        Arguments
        ---------
        - entry: complex type (required)
            - account: string (required)
            - username: string (required)
            - password: string (required)
            - extra: string (optional)
            - has_2fa: boolean (required)
        - password: string (required)

        The password argument is the master password

        Response
        --------
        Success or error message::

            { "status": "success"|"error", "msg": string }

        Status codes
        ------------
        - 200: success
        - 400: various input validation errors
        - 401: not authenticated / password is not correct
        """
        parser = reqparse.RequestParser()
        parser.add_argument("password", type=str, required=True)
        parser.add_argument("entry", type=dict, required=True)
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
                backend.edit_entry(
                    session=db.session,
                    entry_id=entry_id,
                    user_key=args.password,
                    edited_entry=args.entry,
                    user_id=user_id
                )
                return json_success_v2(
                    "successfully edited account %s" % escape(args.entry["account"])
                )
            except NoResultFound:
                return json_error_v2("no such entry", 400)
            except AssertionError:
                return json_error_v2("the given entry does not belong to you", 400)
        else:
            return json_error_v2("Password is not correct", 401)

    @ns.doc(security="apikey")
    @jwt_required
    def post(self, entry_id: int):
        """Decrypt the given entry and return the contents

        Authentication
        --------------
        JWT

        Arguments
        ---------
        - password: string (required)

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
        - 400: various input validation errors
        - 401: not authenticated / password is not correct
        - 500: there are some old entries (version < 4) so this method cannot work
        """
        parser = reqparse.RequestParser()
        parser.add_argument("password", type=str, required=True)
        args = parser.parse_args()

        user_id = get_jwt_identity()["user_id"]
        user = db.session.query(User).filter_by(id=user_id).one()
        if user.authenticate(args.password):
            try:
                entry = db.session.query(Entry)\
                    .filter_by(id=entry_id, user_id=user_id, pinned=False)\
                    .one()
                data = entry.decrypt(args.password)
                return data
            except NoResultFound:
                return json_error_v2("no such entry or the entry does not belong to you", 400)
        else:
            return json_error_v2("Password is not correct", 401)
