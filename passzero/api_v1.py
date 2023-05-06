from datetime import datetime

from flask import Blueprint, escape, session
from sqlalchemy.orm.exc import NoResultFound

from passzero import backend
from passzero.api_utils import (json_error, json_success,
                                requires_json_form_validation, write_json)
from passzero.forms import LoginForm
from passzero.models import db

api_v1 = Blueprint("api_v1", __name__)


class UserNotActiveException(Exception):
    pass


class TokenExpiredException(Exception):
    pass


def __logout():
    if 'email' in session:
        session.pop("email")
    if 'password' in session:
        session.pop("password")
    if 'user_id' in session:
        session.pop("user_id")


@api_v1.route("/api/logout", methods=["POST"])
@api_v1.route("/api/v1/logout", methods=["POST"])
def api_v1_logout():
    """Logout. Destroy current session.

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
    __logout()
    code, data = json_success("Successfully logged out")
    return write_json(code, data)


@api_v1.route("/api/login", methods=["POST"])
@api_v1.route("/api/v1/login", methods=["POST"])
@requires_json_form_validation(LoginForm)
def api_v1_login(request_data):
    """Login. On success, update session cookie.

    Arguments
    ---------
    - email: string (required)
    - password: string (required)

    Response
    --------
    Success or error message::

        { "status": "success"|"error", "msg": string }

    Status codes
    ------------
    - 200: success
    - 400: failed to validate arguments
    - 401: bad username-password combo or account doesn't exist or account isn't activated
    """
    try:
        user = backend.get_account_with_email(db.session, request_data["email"])

        if not user.active:
            raise UserNotActiveException
        if user.authenticate(request_data["password"]):
            session["email"] = user.email
            session["password"] = request_data["password"]
            session["user_id"] = user.id
            # write into last_login
            user.last_login = datetime.utcnow()
            db.session.add(user)
            db.session.commit()
            # craft message to return to user
            msg = "successfully logged in as {email}".format(
                email=escape(session["email"])
            )
            rval = {
                "msg": msg,
                "user_id": user.id,
            }
            return write_json(200, rval)
        else:
            code, data = json_error(401, "Either the email or password is incorrect")
    except NoResultFound:
        code, data = json_error(401, "There is no account with that email")
    except UserNotActiveException:
        code, data = json_error(
            401,
            "The account has not been activated. Check your email!"
        )
    return write_json(code, data)
