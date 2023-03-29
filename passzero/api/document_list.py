from flask_jwt_extended import get_jwt_identity, jwt_required

from flask_restx import Namespace, Resource, reqparse
import werkzeug

from passzero import backend
from passzero.api_utils import json_error_v2
from passzero.models import User, db
from passzero.api.jwt_auth import authorizations


ns = Namespace("DocumentList", authorizations=authorizations)


@ns.route("")
class ApiEntryList(Resource):

    @ns.doc(security="apikey")
    @jwt_required()
    def post(self):
        """Upload a new document for the logged-in user

        Authentication
        --------------
        JWT

        Arguments
        ---------
        - name: string (required)
        - document: File (required)
        - mimetype: string (required)
        - password: string (required)

        Response
        --------
        on success::

            { "document_id": number }

        on error::

            { "status": "error", "msg": string }

        Status codes
        ------------
        - 200: success
        - 400: various input validation errors
        - 401: not authenticated / password is not correct
        """
        parser = reqparse.RequestParser()
        parser.add_argument("name", type=str, required=True)
        parser.add_argument("mimetype", type=str, required=True)
        parser.add_argument("password", type=str, required=True)
        parser.add_argument("document", type=werkzeug.datastructures.FileStorage, location='files')
        args = parser.parse_args()

        user_id = get_jwt_identity()["user_id"]
        user = db.session.query(User).filter_by(id=user_id).one()
        if user.authenticate(args.password):
            encrypted_file = backend.encrypt_document(
                db_session=db.session,
                user_id=user_id,
                master_key=args.password,
                document_name=args.name,
                mimetype=args.mimetype,
                document=args.document,
            )
            return {"document_id": encrypted_file.id}
        else:
            return json_error_v2("Password is not correct", 401)
