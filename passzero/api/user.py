from flask import current_app
from flask_jwt_extended import get_jwt_identity, jwt_required
from flask_restx import Namespace, Resource, ValidationError, reqparse
from sqlalchemy.exc import IntegrityError, NoResultFound

from passzero import backend, change_password
from passzero.api import app_error_codes
from passzero.api.jwt_auth import authorizations
from passzero.api_utils import json_error_v2, json_success_v2
from passzero.models import ApiToken, AuthToken, User, db

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
        """Create a new user. Behaves identically to v1 register user API.

        Arguments
        ---------
        - email: string (required)
        - password: string (required)
        - confirm_password: string (required)

        Response
        --------
        On success or failure, return:

            { "status": status (as string), "msg": message (as string) }

        Status Codes
        ------------
        - 200: On success
        - 400: Various kinds of form validation errors, or user exists
        - 500: Internal error (e.g. email service is down)

        """
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
                ("Your account was successfully created." +
                 " A confirmation email was sent to %s." +
                 " You will need to confirm your email before you can log in.") % args.email
            )
        except backend.UserExistsError as err:
            return json_error_v2(str(err), 400)
        except backend.EmailSendError:
            return json_error_v2("failed to send email", 500)


@ns.route("/register/confirm")
class ApiUserConfirm(Resource):
    def post(self):
        """Confirm the creation of a new user. Behaves identially to main_routes.confirm_signup.

        Arguments
        ---------
        - token: string (required)

        Response
        --------
        On success or failure, return:

            {
                "status": status (as string),
                "msg": message (as string),
                "code": numerical code error message on failure
            }

        Status Codes
        ------------
        - 200: On success
        - 400: Various kinds of form validation errors, or token is invalid or expired
        """
        parser = reqparse.RequestParser()
        parser.add_argument("token", type=str, required=True)
        args = parser.parse_args()
        try:
            token_obj = db.session.query(AuthToken).filter_by(token=args.token).one()
            if token_obj.is_expired():
                current_app.logger.error("Register token has expired")
                # delete old token from database
                db.session.delete(token_obj)
                db.session.commit()
                return json_error_v2("This token has expired", 400,
                                     app_error_code=app_error_codes.AUTH_TOKEN_EXPIRED)
            else:
                # delete the token so it cannot be used again
                db.session.delete(token_obj)
                user = db.session.query(User).filter_by(id=token_obj.user_id).one()
                backend.activate_account(db.session, user)
                current_app.logger.info("Account has been successfully activated using token.")
                return json_success_v2("Account has been activated.")
        except NoResultFound:
            current_app.logger.error("Register token is invalid")
            return json_error_v2("This token is invalid. It may have already been used.", 400,
                                 app_error_code=app_error_codes.AUTH_TOKEN_INVALID)


@ns.route("/me")
class CurrentUser(Resource):
    @ns.doc(security="apikey")
    @jwt_required()
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
    @jwt_required()
    def patch(self):
        """Update the current user. Can update a few fields. Specify the ones you want to update, leave the rest blank.

        Authentication
        --------------
        JWT

        Arguments
        ---------

        - username: string (optional)
        - preferences: dictionary (optional)
            - default_random_password_length: number
            - default_random_passphrase_length: number

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
        parser.add_argument("preferences", type=dict, required=False)
        args = parser.parse_args()
        # update username first to check for failure of uniqueness constraint
        if args.username:
            current_app.logger.info("Updating username for user %d", user.id)
            try:
                user.username = args.username
                db.session.commit()
            except IntegrityError:
                # roll back the transaction
                db.session.rollback()
                return json_error_v2("There is already an account with this username. Usernames must be unique.", 400)

        # update user preferences
        if args.preferences:
            current_app.logger.info("Updating user preferences for user %d", user.id)
            # update the user preferences
            if args.preferences.get("default_random_password_length", None):
                user.default_random_password_length = int(args.preferences["default_random_password_length"])
            if args.preferences.get("default_random_passphrase_length", None):
                user.default_random_passphrase_length = int(args.preferences["default_random_passphrase_length"])
            db.session.add(user)
            db.session.commit()

        return json_success_v2("Successfully updated user")


@ns.route("/delete")
class DeleteUser(Resource):
    """NOTE: we are using a separate endpoint so we are not setting query params with password
    """

    @ns.doc(security="apikey")
    @jwt_required()
    def post(self):
        """Delete all information about the currently logged-in user.

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
        - 400: parameter validation error
        - 401: not authenticated, or password incorrect
        """
        user_id = get_jwt_identity()["user_id"]
        parser = reqparse.RequestParser()
        parser.add_argument("password", type=str, required=True)
        args = parser.parse_args()
        user = db.session.query(User).filter_by(id=user_id).one()

        if user.authenticate(args.password):
            backend.delete_account(db.session, user)
            # revoke all these tokens
            db.session.query(ApiToken).filter_by(user_id=user_id).delete()
            db.session.commit()
            return json_success_v2("Successfully deleted account")
        else:
            return json_error_v2("Invalid master password", 401)


@ns.route("/password")
class ChangePassword(Resource):
    @ns.doc(security="apikey")
    @jwt_required()
    def post(self):
        """Change the master password for the logged-in user.

        Arguments
        ---------
        - old_password: string (required)
        - new_password: string (required)
        - confirm_new_password: string (required)

        Response
        --------
        Success or error message::

            { "status": "success"|"error", "msg": string }

        Status codes
        ------------
        - 200: success
        - 400: failed to validate parameters
        - 401: user is not authenticated, or old password is incorrect
        """
        user_id = get_jwt_identity()["user_id"]
        parser = reqparse.RequestParser()
        parser.add_argument("old_password", type=str, required=True)
        parser.add_argument("new_password", type=str, required=True)
        parser.add_argument("confirm_new_password", type=str, required=True)
        args = parser.parse_args()

        if args.new_password != args.confirm_new_password:
            return json_error_v2("Passwords do not match", 400)

        entries = backend.get_entries(db.session, user_id)
        try:
            backend.decrypt_entries(entries, args.old_password)
        except ValueError:
            msg = "The provided old password is incorrect"
            return json_error_v2(msg, 401)
        ok = change_password.change_password(
            db.session,
            user_id=user_id,
            old_password=args.old_password,
            new_password=args.new_password,
        )
        if ok:
            return json_success_v2("Successfully changed password")
        else:
            return json_error_v2("Old password is incorrect", 401)
