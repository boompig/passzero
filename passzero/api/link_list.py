import logging
import time
from typing import List

from flask_jwt_extended import get_jwt_identity, jwt_required
from flask_restx import Namespace, Resource, reqparse
from sqlalchemy import and_

from .. import backend
from ..api_utils import json_error_v2, json_success_v2
from ..models import Link, User, db
from .jwt_auth import authorizations


def jsonify_links(enc_links: List[Link]) -> List[dict]:
    return [link.to_json() for link in enc_links]


ns = Namespace("LinkList", authorizations=authorizations)
logger = logging.getLogger(__name__)


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
            - service_name: string (required)
            - link: string (required)
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
        link_parser.add_argument("service_name", type=str, required=True, location=("link", ))
        link_parser.add_argument("link", type=str, required=True, location=("link", ))
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
        - password: string (required)

        Response
        --------
        Success or error message::

            { "status": "success"|"error", "msg": string }

        Status codes
        ------------
        - 200: success
        - 401: not authenticated
        """
        parser = reqparse.RequestParser()
        parser.add_argument("password", type=str, required=True)
        args = parser.parse_args()
        identity = get_jwt_identity()
        user = db.session.query(User).filter_by(id=identity["user_id"]).one()
        if user.authenticate(args.password):
            backend.delete_all_links(db.session, user)
            return json_success_v2("Deleted all links")
        else:
            return json_error_v2("Password is not correct", 401)

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
        return jsonify_links(enc_links)


MAX_NUM_DECRYPT = 10


@ns.route("/decrypt")
class DecryptedApiLink(Resource):
    @ns.doc(security="apikey")
    @jwt_required
    def post(self):
        """Return a list of decrypted links.

        Authentication
        --------------
        JWT

        Arguments
        ---------
        - password: string (required)
        - entry_ids: list of integers (required, must be non-empty)

        Response
        --------
        on success::

            [ link-1, link-2, ..., link-n ]

        Exactly what information is returned depends on the link version
        Order is *not* guaranteed to be the same as `entry_ids`

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
        # NOTE: expected type is list of integers
        parser.add_argument("link_ids", type=int, action="append", required=True)
        args = parser.parse_args()

        user_id = get_jwt_identity()["user_id"]
        user = db.session.query(User).filter_by(id=user_id).one()
        if not user.authenticate(args.password):
            return json_error_v2("Password is not correct", 401)

        if len(args.link_ids) > MAX_NUM_DECRYPT:
            return json_error_v2(
                f"Can decrypt a maximum of {MAX_NUM_DECRYPT} links using this method, got {len(args.link_ids)}",
                400
            )

        dec_links = []
        start = time.time()
        query = db.session.query(Link)
        enc_links = query.filter(and_(
            Link.id.in_(args.link_ids),
            Link.user_id == user_id,
        )).all()
        end = time.time()
        logger.debug(f"Took {end - start:.2f}ms to retrieve links from DB")
        start = time.time()
        for enc_link in enc_links:
            dec_link = enc_link.decrypt(args.password)
            dec_links.append(dec_link.to_json())
        end = time.time()
        logger.debug(f"Took {end - start:.2f}ms to decrypt links")
        return dec_links
