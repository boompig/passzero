from flask_restx import Namespace, Resource, reqparse, ValidationError
from flask_jwt_extended import jwt_required, get_jwt_identity
from sqlalchemy.exc import IntegrityError

from passzero.api_utils import json_error_v2, json_success_v2
from passzero.models import User, db
from passzero.api.jwt_auth import authorizations
from passzero import backend


ns = Namespace("User", authorizations=authorizations)


def username(min_len: int, max_len: int):
    """
    This is the parametrized validation function for usernames
    Uniqueness is not checked here, just whether that username is allowed
    """
    def validate(s: str):
        if not isinstance(s, str):
            raise ValidationError("Parameter must be a string")
        elif "." in s or "@" in s:
            raise ValidationError("Parameter may not contain the characters '.' or '@'")
        elif s in ["admin", "root"]:
            raise ValidationError(f"{s} is a reserved username")
        if len(s) < min_len:
            raise ValidationError(f"Parameter must be at least {min_len} characters long")
        elif len(s) > max_len:
            raise ValidationError(f"Parameter must be at most {max_len} characters long")
        else:
            return s
    return validate


@ns.route("/register")
class ApiUser(Resource):
    def post(self):
        """Create a new user. Behaves identically to v1 register user API"""
        parser = reqparse.RequestParser()
        parser.add_argument("email", type=str, required=True)
        parser.add_argument("password", type=str, required=True)
        parser.add_argument("confirm_password", type=str, required=True)
        args = parser.parse_args()

        if args.password != args.confirm_password:
            return json_error_v2("password and confirm_password must match", 400)

        try:
            backend.create_new_account(
                db_session=db.session,
                email=args.email,
                password=args.password,
            )
            return json_success_v2(
                "Successfully created (inactive) account with email %s" % args.email
            )
        except backend.UserExistsError as err:
            return json_error_v2(str(err), 400)
        except backend.EmailSendError:
            return json_error_v2("failed to send email", 500)


@ns.route("/me")
class CurrentUser(Resource):
    @ns.doc(security="apikey")
    @jwt_required
    def get(self):
        """Return details about the current user

        Authentication
        --------------
        JWT

        Arguments
        ---------
        none

        Response
        --------
        on success::

            user

        Exactly what information is returned depends on `models/user.py` object

        on error::

            {"status": "error", "msg": string}

        Status codes
        ------------
        - 200: success
        - 401: not authorized
        """
        user_id = get_jwt_identity()["user_id"]
        user = db.session.query(User).filter_by(id=user_id).one()
        return user.to_json()

    @ns.doc(security="apikey")
    @jwt_required
    def patch(self):
        """Update the current user. Can update a few fields. Specify the ones you want to update, leave the rest blank.

        Authentication
        --------------
        JWT

        Arguments
        ---------

        - username: string (optional)

        Response
        --------
        Success or error message::

            { "status": "success"|"error", "msg": string }

        Status codes
        ------------
        - 200: success
        - 401: not authorized
        """
        user_id = get_jwt_identity()["user_id"]
        user = db.session.query(User).filter_by(id=user_id).one()
        parser = reqparse.RequestParser()
        parser.add_argument("username", type=username(2, 16), required=False)
        args = parser.parse_args()
        # update username first to check for failure of uniqueness constraint
        if args.username:
            try:
                user.username = args.username
                db.session.commit()
            except IntegrityError:
                # roll back the transaction
                db.session.rollback()
                return json_error_v2("There is already an account with this username. Usernames must be unique.", 400)

        return json_success_v2("Successfully updated user")
