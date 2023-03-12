"""
Manages the API id tokens
"""

from datetime import datetime, timezone

from flask import current_app, session
from flask_jwt_extended import (create_access_token, decode_token,
                                get_jwt_identity, jwt_required)
from sqlalchemy.orm.exc import NoResultFound

from flask_restx import Namespace, Resource, reqparse

from passzero import backend
from passzero import crypto_utils
from passzero.api_utils import json_error_v2, json_success_v2, requires_json_auth
from passzero.models import ApiToken, User, db
from passzero.api.jwt_auth import authorizations


class UserNotActiveException(Exception):
    pass


ns = Namespace("ApiToken", authorizations=authorizations)


@ns.route("")
class ApiTokenResource(Resource):

    def create_token_and_add_to_database(self, user_id: int) -> str:
        """Create a new JTI token and add it to the database.
        :param used_id:     User ID
        :return:            Token text"""
        token = create_access_token(identity={
            "user_id": user_id
        })
        issue_time = datetime.now(timezone.utc)
        decoded_token = decode_token(token)
        expire_time = datetime.fromtimestamp(decoded_token["exp"], timezone.utc)
        api_token = ApiToken(
            user_id=user_id,
            token=token,
            token_identity=decoded_token["jti"],
            issue_time=issue_time,
            expire_time=expire_time
        )
        db.session.add(api_token)
        db.session.commit()
        return token

    @ns.doc(security="session-cookie")
    @requires_json_auth
    def get(self):
        """Return the current token for the logged-in user

        Arguments
        ---------
        none

        Response
        --------
        Token on success::

            { "token": string }

        On failure, error message::

            { "status": "error", "msg": string }

        Status codes
        ------------
        - 200: success
        - 401: not authenticated
        """
        token = self.maybe_create_token_and_add_to_database(session["user_id"])
        return {"token": token}

    def maybe_create_token_and_add_to_database(self, user_id: int) -> str:
        try:
            # there should only be a single token that is currently valid
            api_token = db.session.query(ApiToken).filter_by(user_id=user_id).one()
            if api_token.is_expired():
                db.session.delete(api_token)
                db.session.commit()
                # this is the JTI
                token = self.create_token_and_add_to_database(user_id)
                return token
            else:
                return api_token.token
        except NoResultFound:
            # the token has been blacklisted
            token = self.create_token_and_add_to_database(session["user_id"])
            return token

    def post(self):
        """Login. On success, return a token.

        Arguments
        ---------
        - email: string (one of email or username is required)
        - username: string (one of email or username is required)
        - password: string (required)

        Response
        --------
        On success::

            { "token": string }

        On error::

            { "status": "error", "msg": string }

        Status codes
        ------------
        - 200: success
        - 400: failed to validate arguments
        - 401: bad username-password combo or account doesn't exist or account isn't activated
        """
        parser = reqparse.RequestParser()
        parser.add_argument("email", type=str, required=False)
        parser.add_argument("username", type=str, required=False)
        parser.add_argument("password", type=str, required=True)
        args = parser.parse_args()

        if not args.email and not args.username:
            return json_error_v2("One of email or username is required", 400)
        elif args.email and args.username:
            return json_error_v2("Specify only one of email and username", 400)
        elif args.email and "@" not in args.email:
            return json_error_v2("Email must contain an '@' symbol", 400)
        elif args.username and "@" in args.username:
            return json_error_v2("Usernames may not contain an '@' symbol", 400)

        try:
            if args.username:
                user = backend.get_account_with_username(db.session, args.username)
            else:
                user = backend.get_account_with_email(db.session, args.email)
            if not user.active:
                raise UserNotActiveException
            if user.authenticate(args.password):
                session["email"] = user.email
                session["password"] = args.password
                session["user_id"] = user.id

                # if the type of password hashing algorithm is old, rehash their password with the new algorithm
                if user.password_hash_algo != User.DEFAULT_PASSWORD_HASH_ALGO:
                    current_app.logger.info(
                        "Detected old hash algo (%d) for user %d's password. Rehashing password with latest algo...",
                        user.password_hash_algo,
                        user.id
                    )
                    assert isinstance(user.salt, str)
                    assert isinstance(args.password, str)
                    # note that we are not changing the password
                    hashed_password = crypto_utils.get_hashed_password(
                        password=args.password,
                        salt=user.salt.encode("utf-8"),
                        hash_algo=User.DEFAULT_PASSWORD_HASH_ALGO
                    )
                    user.password = hashed_password.decode("utf-8")
                    user.password_hash_algo = User.DEFAULT_PASSWORD_HASH_ALGO
                    user.last_modified_at = datetime.utcnow()

                # write into last_login
                user.last_login = datetime.utcnow()
                db.session.add(user)
                db.session.commit()

                token = self.maybe_create_token_and_add_to_database(user.id)
                return {"token": token}
            else:
                return json_error_v2("Either the email or password is incorrect", 401)
        except NoResultFound:
            return json_error_v2("There is no account with that email", 401)
        except UserNotActiveException:
            return json_error_v2("The account has not been activated. Check your email!", 401)

    @ns.doc(security="apikey")
    @jwt_required()
    def delete(self):
        """Logout. Destroy current token.

        Arguments
        ---------
        none

        Response
        --------
        Success or error message::

            { "status": "success", "msg": string }

        Status codes
        ------------
        - 200: success
        """
        user_id = get_jwt_identity()["user_id"]
        # revoke all these tokens
        db.session.query(ApiToken).filter_by(user_id=user_id).delete()
        db.session.commit()
        return json_success_v2("Successfully destroyed token")
