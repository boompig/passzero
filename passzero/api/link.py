from flask import escape
from flask_jwt_extended import get_jwt_identity, jwt_required
from sqlalchemy.orm.exc import NoResultFound

from flask_restplus import Namespace, Resource, reqparse

from .. import backend
from ..api_utils import json_error_v2, json_success_v2
from ..models import Link, User, db
from .jwt_auth import authorizations

ns = Namespace("link", authorizations=authorizations)


@ns.route("")
class ApiLink(Resource):

    @ns.doc(security="apikey")
    @jwt_required
    def delete(self, link_id: int):
        """Delete the link with the given ID.

        Authentication
        --------------
        JWT

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
        - 400: link does not exist or does not belong to logged-in user
        """
        user_id = get_jwt_identity()["user_id"]
        try:
            link = db.session.query(Link).filter_by(id=link_id).one()
            assert link.user_id == user_id
            db.session.delete(link)
            db.session.commit()
            return json_success_v2("successfully deleted link with ID %d" % link_id)
        except NoResultFound:
            return json_error_v2("no such link", 400)
        except AssertionError:
            return json_error_v2("the given link does not belong to you", 400)

    @ns.doc(security="apikey")
    @jwt_required
    def patch(self, link_id: int):
        """Update the specified link.

        Authentication
        --------------
        JWT

        Arguments
        ---------
        - link: complex type (required)
            - service_name: string (required)
            - link: string (required)
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
        - 401: password is not correct
        """
        parser = reqparse.RequestParser()
        parser.add_argument("password", type=str, required=True)
        parser.add_argument("link", type=dict, required=True)
        args = parser.parse_args()

        link_parser = reqparse.RequestParser()
        link_parser.add_argument("service_name", type=str, required=True, location=("link", ))
        link_parser.add_argument("link", type=str, required=True, location=("link", ))
        link_parser.parse_args(req=args)

        user_id = get_jwt_identity()["user_id"]
        user = db.session.query(User).filter_by(id=user_id).one()
        if user.authenticate(args.password):
            try:
                backend.edit_link(
                    session=db.session,
                    link_id=link_id,
                    user_key=args.password,
                    edited_link=args.link,
                    user_id=user_id
                )
                return json_success_v2(
                    "successfully edited account %s" % escape(args.link["account"])
                )
            except NoResultFound:
                return json_error_v2("no such link", 400)
            except AssertionError:
                return json_error_v2("the given link does not belong to you", 400)
        else:
            return json_error_v2("Password is not correct", 401)

    @ns.doc(security="apikey")
    @jwt_required
    def post(self, link_id: int):
        """Decrypt the given link and return the contents

        Authentication
        --------------
        JWT

        Arguments
        ---------
        - password: string (required)

        Response
        --------
        on success::

            link

        Exactly what information is returned depends on the link version

        on error::

            { "status": "error", "msg": string }

        Status codes
        ------------
        - 200: success
        - 400: various input validation errors
        - 401: password is not correct
        """
        parser = reqparse.RequestParser()
        parser.add_argument("password", type=str, required=True)
        args = parser.parse_args()

        user_id = get_jwt_identity()["user_id"]
        user = db.session.query(User).filter_by(id=user_id).one()
        if user.authenticate(args.password):
            try:
                link = db.session.query(Link)\
                    .filter_by(id=link_id, user_id=user_id, pinned=False)\
                    .one()
                data = backend._decrypt_row(link, args.password)
                return data
            except NoResultFound:
                return json_error_v2("no such link or the link does not belong to you", 400)
        else:
            return json_error_v2("Password is not correct", 401)
