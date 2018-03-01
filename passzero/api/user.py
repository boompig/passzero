# from flask_restful import Resource
from flask import Blueprint, session

from .. import backend, change_password
from ..api_utils import (json_error, json_success, requires_csrf_check,
                        requires_json_auth, requires_json_form_validation,
                        write_json)
from ..forms import UpdatePasswordForm
from ..models import db

user_api = Blueprint("user_api", __name__)

@user_api.route("/password", methods=["PATCH", "PUT"])
@requires_json_auth
@requires_csrf_check
@requires_json_form_validation(UpdatePasswordForm)
def api_v1_update_user_password(request_data: UpdatePasswordForm):
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
    - 403: CSRF check failed
    - 500: server error, or old password is incorrect
    """
    entries = backend.get_entries(db.session, session["user_id"])
    try:
        backend.decrypt_entries(entries, session['password'])
    except ValueError:
        msg = "Error decrypting entries. This means the old password is most likely incorrect"
        code, data = json_error(500, msg)
        return write_json(code, data)
    status = change_password.change_password(
        db.session,
        user_id=session['user_id'],
        old_password=request_data['old_password'],
        new_password=request_data['new_password']
    )
    if status:
        session['password'] = request_data['new_password']
        code, data = json_success("Successfully changed password")
    else:
        code, data = json_error(401, "Old password is incorrect")
    return write_json(code, data)


@api_v1.route("/api/v1/user/signup", methods=["POST"])
@requires_json_form_validation(SignupForm)
def signup_api(request_data: SignupForm):
    """First step of user registration.
    Create an inactive user and send an email to the specified email address.
    The account cannot be logged-into until it has been activated via the activation link in the email.

    Arguments
    ---------
    - email: string (required)
    - password: string (required)
    - confirm_password: string (required)

    Response
    --------
    Success or error message::

        { "status": "success"|"error", "msg": string }

    Status codes
    ------------
    - 200: success
    - 400: account already exists
    - 403: CSRF token validation failed
    - 500: failed to send email
    """
    try:
        user = backend.get_account_with_email(db.session, request_data["email"])
    except NoResultFound:
        token = AuthToken()
        token.random_token()
        if send_confirmation_email(request_data["email"], token.token):
            user = backend.create_inactive_user(
                db.session,
                request_data["email"],
                request_data["password"]
            )
            token.user_id = user.id;
            # now add token
            db.session.add(token)
            change_password.create_pinned_entry(db.session, user.id, request_data["password"])
            db.session.commit()
            code, data = json_success(
                "Successfully created account with email %s" % request_data['email']
            )
        else:
            code, data = json_internal_error("failed to send email")
    else:
        if user.active:
            code, data = json_error(400,
                "an account with this email address already exists")
        else:
            code, data = json_error(400,
                "This account has already been created. Check your inbox for a confirmation email.")
    return write_json(code, data)


@api_v1.route("/api/v1/user/activate", methods=["POST"])
@requires_json_form_validation(ActivateAccountForm)
def confirm_signup_api(request_data: ActivateAccountForm):
    """Second and final step of user registration.
    Activate the previously created inactive account.
    This API is meant to be hit when a user clicks a link in their email.

    Arguments
    ---------
    - token: string (required)

    Response
    --------
    Success or error message::

        { "status": "success"|"error", "msg": string }

    Status codes
    ------------
    - 200: success
    - 400: account already activated
    - 401: token is invalid
    - 403: CSRF token validation failed
    """
    try:
        token = request_data['token']
        token_obj = db.session.query(AuthToken).filter_by(token=token).one()
        if token_obj.is_expired():
            # delete old token from database
            db.session.delete(token_obj)
            db.session.commit()
            code, data = json_error(401, "token has expired")
        else:
            # token deleted when password changed
            db.session.delete(token_obj)
            user = db.session.query(User).filter_by(id=token_obj.user_id).one()
            if user.active:
                code, data = json_error(400, "The account has already been activated")
            else:
                backend.activate_account(db.session, user)
                code, data = json_success("Account has been activated")
    except NoResultFound:
        code, data = json_error(401, "token is invalid")
    return write_json(code, data)

@api_v1.route("/api/v1/user/recover", methods=["POST"])
@requires_csrf_check
@requires_json_form_validation(RecoverPasswordForm)
def api_v1_user_recover(request_data: RecoverPasswordForm):
    """First step of account recovery for the specified user.
    Send an account recovery token to the user's email address.

    Arguments
    ---------
    - email: string (required)

    Response
    --------
    Success or error message::

        { "status": "success"|"error", "msg": string }

    Status codes
    ------------
    - 200: success
    - 400: failed to validated parameters
    - 401: no account for this email
    - 500: internal server error, or email failed to send
    """
    try:
        user = db.session.query(User).filter_by(email=request_data['email']).one()
        # send a reset token to the email
        token = AuthToken()
        token.user_id = user.id
        token.random_token()
        db.session.add(token)
        db.session.commit()
        if send_recovery_email(user.email, token.token):
            code, data = json_success("Recovery email sent to your email address")
        else:
            logging.error("Failed to send email")
            code, data = json_internal_error("Failed to send email")
    except NoResultFound:
        code, data = json_error(401, "no such email")
    return write_json(code, data)


@api_v1.route("/api/v1/user/preferences", methods=["GET"])
@requires_json_auth
def api_v1_get_user_preferences():
    """Get various account preferences for the logged-in user.

    Arguments
    ---------
    none

    Response
    --------
    Success or error message::

        { pref-1-key: pref-1-value, ... }

    For specific preference values look in models.py

    Status codes
    ------------
    - 200: success
    - 401: user is not authenticated
    """
    user = db.session.query(User).filter_by(id=session["user_id"]).one()
    data = {
        "default_random_password_length": user.default_random_password_length,
        "default_random_passphrase_length": user.default_random_passphrase_length
    }
    return write_json(200, data)

@api_v1.route("/api/v1/user/preferences", methods=["PATCH", "PUT"])
@requires_json_auth
@requires_csrf_check
@requires_json_form_validation(UpdatePreferencesForm)
def api_v1_update_user_preferences(request_data: UpdatePreferencesForm):
    """Update various account preferences for the logged-in user.
    Only have to specify those preferences that you want to change.
    Preferences which are not specified will not change.

    Arguments
    ---------
    - default_random_password_length: string (optional)
    - default_random_passphrase_length: string (optional)

    Response
    --------
    Success or error message::

        { "status": "success"|"error", "msg": string }

    Status codes
    ------------
    - 200: success
    - 400: failed to validate parameters
    - 401: user is not authenticated
    - 403: CSRF check failed
    - 500: internal server error
    """
    user = db.session.query(User).filter_by(id=session["user_id"]).one()
    if request_data.get("default_random_password_length", None):
        user.default_random_password_length = int(request_data["default_random_password_length"])
    if request_data.get("default_random_passphrase_length", None):
        user.default_random_passphrase_length = int(request_data["default_random_passphrase_length"])
    db.session.add(user)
    db.session.commit()
    code, data = json_success("Preferences have been updated")
    return write_json(code, data)

@api_v1.route("/api/v1/user/recover/confirm", methods=["POST"])
@requires_json_form_validation(ConfirmRecoverPasswordForm)
def recover_password_confirm_api(request_data: ConfirmRecoverPasswordForm):
    """
    Second and final step of account recovery for the specified user.
    This API is meant to be hit when the user clicks the link in a recovery email.
    Check the token is valid, then nuke all the entries and reset the password.

    Arguments
    ---------
    - token: string (required)
    - password: string (required)
    - confirm_password: string (required)

    Response
    --------
    Success or error message::

        { "status": "success"|"error", "msg": string }

    Status codes
    ------------
    - 200: success
    - 400: token is invalid
    """
    try:
        token = db.session.query(AuthToken).filter_by(token=request_data['token']).one()
        if token.is_expired():
            raise TokenExpiredException
        user = db.session.query(User).filter_by(id=token.user_id).one()
        # 1) change the user's password
        user.change_password(request_data['password'])
        # 2) activate user's account, if not already active
        user.active = True
        all_entries = db.session.query(Entry).filter_by(user_id=token.user_id).all()
        # 2) delete all user's entries
        for entry in all_entries:
            db.session.delete(entry)
        # 3) delete the token used to make this change
        db.session.delete(token)
        db.session.commit()
        code, data = json_success("successfully changed password")
    except NoResultFound:
        code, data = json_error(400, "token is invalid")
    except TokenExpiredException:
        # delete old token
        db.session.delete(token)
        db.session.commit()
        # return error via JSON
        code, data = json_error(400, "token has expired")
    return write_json(code, data)


@api_v1.route("/api/v1/user", methods=["DELETE"])
@requires_json_auth
@requires_csrf_check
@requires_json_form_validation(DeleteUserForm)
def delete_user_api(request_data: DeleteUserForm):
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
    - 403: CSRF token validation failed
    """
    user = db.session.query(User).filter_by(id=session["user_id"]).one()
    if user.authenticate(request_data["password"]):
        # delete all entries
        entries = db.session.query(Entry).filter_by(user_id=user.id).all()
        for entry in entries:
            db.session.delete(entry)
        # delete all the documents
        docs = db.session.query(EncryptedDocument).filter_by(user_id=user.id).all()
        for doc in docs:
            db.session.delete(doc)
        # delete all auth tokens
        tokens = db.session.query(AuthToken).filter_by(user_id=user.id).all()
        for token in tokens:
            db.session.delete(token)
        # delete the user
        db.session.delete(user)
        db.session.commit()
        code, data = json_success(
            "The user and all associated information has been deleted. You have been logged out.")
        # have to log out
        __logout()
    else:
        code, data = json_error(401, "Invalid master password")
    return write_json(code, data)

