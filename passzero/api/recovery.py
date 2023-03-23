from flask import current_app
from flask_restx import Namespace, Resource, reqparse
from sqlalchemy.orm.exc import NoResultFound

from passzero import backend, email
from passzero.api.jwt_auth import authorizations
from passzero.api_utils import json_error_v2, json_success_v2
from passzero.models import AuthToken, User, db

ns = Namespace("recovery", authorizations=authorizations)


@ns.route("")
class Recovery(Resource):
    def post(self):
        """Begin the recovery process for the user's account.
        Note that this does *not* require a token

        Arguments
        ---------
        - email: string (required)
        - accept_risks: boolean (required)

        Response
        --------
        Success or error message::

        { "status": "success"|"error", "msg": string }

        Status Codes
        ------------
        - 200: success
        - 400: failed to validated parameters
        - 401: no account for this email
        - 500: internal server error, or email failed to send
        """
        parser = reqparse.RequestParser()
        parser.add_argument("email", type=str, required=True)
        parser.add_argument("accept_risks", type=bool, required=True)
        args = parser.parse_args()

        if not args.accept_risks:
            return json_error_v2("accept_risks must be true", 400)

        try:
            user = db.session.query(User).filter_by(email=args.email).one()
            # send a reset token to the email
            token = AuthToken()
            token.user_id = user.id
            token.random_token()
            db.session.add(token)
            db.session.commit()
            if email.send_recovery_email(user.email, token.token):
                return json_success_v2("A recovery email has been sent to your email address.")
            else:
                current_app.logger.error("Failed to send email")
                return json_error_v2("Failed to send email", 500)
        except NoResultFound:
            current_app.logger.error("User tried to recover an account with email %s, no such email",
                                     args.email)
            return json_error_v2("There is no account with this email.", 401)


@ns.route("/email")
class RecoveryTokenEmail(Resource):

    def get(self):
        """Get the user's email given their recovery token"""
        parser = reqparse.RequestParser()
        parser.add_argument("token", type=str, required=True)
        args = parser.parse_args()

        try:
            token_obj = db.session.query(AuthToken).filter_by(token=args.token).one()
            if token_obj.is_expired():
                return json_error_v2("The provided token has expired", 401)
            else:
                # guaranteed to exist
                user = db.session.query(User).filter_by(id=token_obj.user_id).one()
                return {
                    "user": {
                        "email": user.email,
                    },
                    "token": {
                        "issue_time": token_obj.issue_time.isoformat(),
                    },
                }
        except NoResultFound:
            return json_error_v2("This token is invalid", 401)


@ns.route("/confirm")
class ConfirmRecovery(Resource):

    def post(self):
        """Confirm the recovery of the account."""
        parser = reqparse.RequestParser()
        parser.add_argument("token", type=str, required=True)
        parser.add_argument("password", type=str, required=True)
        parser.add_argument("confirm_password", type=str, required=True)
        parser.add_argument("accept_risks", type=bool, required=True)
        args = parser.parse_args()

        if args.password != args.confirm_password:
            return json_error_v2("password and confirm_password do not match", 400)

        try:
            token_obj = db.session.query(AuthToken).filter_by(token=args.token).one()
            assert not token_obj.is_expired()
            # guaranteed to exist
            user = db.session.query(User).filter_by(id=token_obj.user_id).one()
            backend.recover_account_confirm(
                db.session,
                user,
                args.password,
            )

            # now we delete the auth token
            auth_tokens_q = db.session.query(AuthToken).filter_by(user_id=user.id)
            auth_tokens_q.delete()

            return json_success_v2("Your account has been successfully reset with the provided password." +
                                   " Please navigate to the login page and log in with this new password.")
        except AssertionError:
            return json_error_v2("This token is expired.", 401)
        except NoResultFound:
            current_app.logger.error("User tried to recover an account with invalid token")
            return json_error_v2("This token is invalid.", 401)
