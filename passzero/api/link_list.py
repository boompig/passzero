from flask_jwt_extended import get_jwt_identity, jwt_required
from typing import List

from flask_restplus import Namespace, Resource, reqparse

from .. import backend
from ..api_utils import json_error_v2, json_success_v2
from ..models import Link, User, db
from .jwt_auth import authorizations


def jsonify_links_pool(link: Link) -> dict:
    assert link.version >= 4
    out = link.to_json()
    # remove the encrypted elements in order to conserve bandwidth
    out.pop("username")
    out.pop("password")
    out.pop("extra")
    return out


def jsonify_links(enc_links: List[Link]):
    return [jsonify_links_pool(link) for link in enc_links]


ns = Namespace("LinkList", authorizations=authorizations)


@ns.route("")
class ApiLinkList(Resource):

    @ns.doc(security="apikey")
    @jwt_required
    def post(self):
        """Create a new link for the logged-in user.

        Authentication
        --------------
        JWT

        Arguments
        ---------
        - link: dict (required)
            - account: string (required)
            - username: string (required)
            - password: string(required)
            - extra: string (optional)
            - has_2fa: boolean (required)
        - password: string (required)

        Response
        --------
        on success::

            { "link_id": number }

        on error::

            { "status": "error", "msg": string }

        Status codes
        ------------
        - 200: success
        - 400: various input validation errors
        - 401: not authenticated / password is not correct
        """
        parser = reqparse.RequestParser()
        parser.add_argument("link", type=dict, required=True)
        parser.add_argument("password", type=str, required=True)
        args = parser.parse_args()

        link_parser = reqparse.RequestParser()
        link_parser.add_argument("account", type=str, required=True, location=("link", ))
        link_parser.add_argument("username", type=str, required=True, location=("link", ))
        link_parser.add_argument("password", type=str, required=True, location=("link", ))
        link_parser.add_argument("extra", required=False, type=str, default="", location=("link", ))
        link_parser.add_argument("has_2fa", required=True, type=bool, location=("link", ))
        link_parser.parse_args(req=args)
        user_id = get_jwt_identity()["user_id"]
        user = db.session.query(User).filter_by(id=user_id).one()
        if user.authenticate(args.password):
            link = backend.insert_link_for_user(
                db_session=db.session,
                dec_link=args.link,
                user_id=user_id,
                user_key=args.password
            )
            return {"link_id": link.id}
        else:
            return json_error_v2("Password is not correct", 401)

    @ns.doc(security="apikey")
    @jwt_required
    def delete(self):
        """Delete *all* links for the logged-in user.

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
        - 401: not authenticated
        """
        identity = get_jwt_identity()
        user = db.session.query(User).filter_by(id=identity["user_id"]).one()
        backend.delete_all_links(db.session, user)
        return json_success_v2("Deleted all links")

    @ns.doc(security="apikey")
    @jwt_required
    def get(self):
        """Return a list of encrypted links.

        Authentication
        --------------
        JWT

        Arguments
        ---------
        none

        Response
        --------
        on success::

            [ link-1, link-2, ..., link-n ]

        exactly what information is returned depends on the link version

        on error::

            { "status": "error", "msg": string }

        Status codes
        ------------
        - 200: success
        - 500: there are some old links (version < 4) so this method cannot work
        """
        user_id = get_jwt_identity()["user_id"]
        enc_links = backend.get_links(db.session, user_id)
        if any([link.version < 4 for link in enc_links]):
            return json_error_v2("This method does not work if there are links below version 4", 500)
        return jsonify_links(enc_links)
