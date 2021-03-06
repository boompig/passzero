import logging
from datetime import datetime
from io import BytesIO

from flask import Blueprint, escape, session, abort, send_file
from sqlalchemy.orm.exc import NoResultFound

from . import backend, change_password
from .api_utils import (generate_csrf_token, json_error, json_internal_error,
                        json_success, requires_csrf_check, requires_json_auth,
                        requires_json_form_validation, write_json)
from .forms import (ActivateAccountForm, ConfirmRecoverPasswordForm,
                    DeleteUserForm, LoginForm, NewEntryForm,
                    RecoverPasswordForm, SignupForm, UpdatePasswordForm,
                    UpdatePreferencesForm,
                    NewDocumentForm)
from .email import send_confirmation_email, send_recovery_email
from .models import AuthToken, Entry, User, db, EncryptedDocument

api_v1 = Blueprint("api_v1", __name__)


class UserNotActiveException(Exception):
    pass


class TokenExpiredException(Exception):
    pass


@api_v1.route("/api/csrf_token", methods=["GET"])
@api_v1.route("/api/v1/csrf_token", methods=["GET"])
def api_v1_get_csrf_token():
    """Get CSRF token for current user's session.

    Arguments
    ---------
    none

    Response
    --------
    CSRF token as string

    Status codes
    ------------
    - 200: success
    """
    # make sure there is a CSRF token
    token = generate_csrf_token()
    return write_json(200, token)


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
            code, data = json_success(msg)
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


#  -------------- DOCUMENTS BEGIN

@api_v1.route("/api/v1/docs", methods=["GET"])
@requires_json_auth
def api_v1_get_docs():
    """Retrieve all saved documents for the logged-in user
    The document contents will be encrypted.

    Arguments
    ---------
    none

    Response
    --------
    on success::

        [doc-1, doc-2, ... doc-n]

    a document's object looks like this::

        {
            "id": number,
            "name": string,
            "contents": binary
        }

    The contents will be encrypted

    on error::

        { "status": "error", "msg": string }

    Status codes
    ------------
    - 200: success
    - 401: user is not logged in
    """
    docs = db.session.query(EncryptedDocument).filter_by(user_id=session["user_id"]).all()
    rval = [doc.to_json() for doc in docs]
    return write_json(200, rval)


@api_v1.route("/api/v1/docs/<int:doc_id>", methods=["GET"])
@requires_json_auth
def api_v1_decrypt_doc(doc_id):
    """
    Decrypt the specified document and return the *resource*

    Arguments
    ---------
    none

    Response
    --------
    on success::

        file

    on error::

        blank page with error code

    Status codes
    ------------
    - 200: success
    - 400: document does not exist or does not belong to logged-in user
    - 401: user is not logged in
    """
    try:
        enc_doc = db.session.query(EncryptedDocument).\
            filter_by(id=doc_id, user_id=session["user_id"]).one()
        dec_doc = enc_doc.decrypt(session["password"])
        f = BytesIO(dec_doc.contents)
        mimetype = dec_doc.mimetype
        # read the content type
        if mimetype.startswith("text/"):
            # otherwise client won't display it properly
            mimetype = "text/plain"
        return send_file(
            f, mimetype=mimetype,
            as_attachment=False,
        )
    except NoResultFound:
        abort(400,
              "Document ID does not correspond to the document"
              "or the document does not belong to you")


@api_v1.route("/api/v1/docs", methods=["POST"])
@requires_json_auth
@requires_csrf_check
@requires_json_form_validation(NewDocumentForm)
def api_v1_create_doc(form_data: NewDocumentForm):
    """Upload a new document for the logged-in user

    Arguments
    ---------
    - name: string (required)
    - document: File (required)
    - mimetype: string (required)

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
    - 401: not authenticated
    - 403: CSRF check failed
    """
    encrypted_file = backend.encrypt_document(
        db.session,
        session["user_id"],
        session["password"],
        document_name=form_data["name"],
        mimetype=form_data["mimetype"],
        document=form_data["document"]
    )
    return write_json(200, {"document_id": encrypted_file.id})


@api_v1.route("/api/v1/docs/<int:document_id>", methods=["PUT"])
@requires_json_auth
@requires_csrf_check
@requires_json_form_validation(NewDocumentForm)
def api_v1_edit_doc(form_data: NewDocumentForm, document_id: int):
    """Upload a new document for the logged-in user

    Arguments
    ---------
    - name: string (required)
    - document: File (required)
    - mimetype: string (required)

    Response
    --------
    on success::

        { "status": "success" }

    on error::

        { "status": "error", "msg": string }

    Status codes
    ------------
    - 200: success
    - 400: various input validation errors
    - 401: not authenticated
    - 403: CSRF check failed
    """
    code = 200
    data = {}  # type: dict
    try:
        backend.edit_document(
            session=db.session,
            document_id=document_id,
            master_key=session["password"],
            form_data=form_data,
            user_id=session["user_id"]
        )
        code, data = json_success("Successfully edited document")
    except NoResultFound:
        code, data = json_error(400, "no such document")
    except backend.UserNotAuthorizedError:
        code, data = json_error(400, "the given document does not belong to you")
    return write_json(code, data)


@api_v1.route("/api/v1/docs/<int:doc_id>", methods=["DELETE"])
@requires_json_auth
@requires_csrf_check
def api_v1_delete_doc(doc_id: int):
    """Delete the document with the given ID.

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
    - 400: document does not exist or does not belong to logged-in user
    - 401: not authenticated
    - 403: CSRF check failed
    """
    try:
        enc_doc = db.session.query(EncryptedDocument).filter_by(id=doc_id).one()
        assert enc_doc.user_id == session['user_id']
        db.session.delete(enc_doc)
        db.session.commit()
        code, data = json_success("successfully deleted document with ID {}".format(
            doc_id))
    except NoResultFound:
        code, data = json_error(400, "no such document")
    except AssertionError:
        code, data = json_error(400, "the given document does not belong to you")
    return write_json(code, data)


#  -------------- DOCUMENTS END
#  -------------- ENTRIES BEGIN

@api_v1.route("/api/entries", methods=["GET"])
@api_v1.route("/api/v1/entries", methods=["GET"])
@requires_json_auth
def api_v1_get_entries():
    """Retrieve all decrypted entries for the logged-in user

    Arguments
    ---------
    none

    Response
    --------
    on success::

        [entry-1, entry-2, ... entry-n]

    The entry details depend on which version entries the user has.
    For details see passzero/models.py.

    on error::

        { "status": "error", "msg": string }

    Status codes
    ------------
    - 200: success
    - 401: user is not logged in
    """
    code = 200
    entries = backend.get_entries(db.session, session["user_id"])
    dec_entries = backend.decrypt_entries(entries, session['password'])
    data = dec_entries
    return write_json(code, data)


@api_v1.route("/api/entries/<int:entry_id>", methods=["DELETE"])
@api_v1.route("/api/v1/entries/<int:entry_id>", methods=["DELETE"])
@requires_json_auth
@requires_csrf_check
def api_v1_delete_entry(entry_id: int):
    """Delete the entry with the given ID.

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
    - 400: entry does not exist or does not belong to logged-in user
    - 401: not authenticated
    - 403: CSRF check failed
    """
    try:
        entry = db.session.query(Entry).filter_by(id=entry_id).one()
        assert entry.user_id == session['user_id']
        db.session.delete(entry)
        db.session.commit()
        code, data = json_success("successfully deleted entry with ID %d" % entry_id)
    except NoResultFound:
        code, data = json_error(400, "no such entry")
    except AssertionError:
        code, data = json_error(400, "the given entry does not belong to you")
    return write_json(code, data)


@api_v1.route("/api/v1/entries", methods=["POST"])
@requires_json_auth
@requires_csrf_check
@requires_json_form_validation(NewEntryForm)
def api_v1_new_entry(request_data: NewEntryForm):
    """Create a new entry for the logged-in user.

    Arguments
    ---------
    - account: string (required)
    - username: string (required)
    - password: string (required)
    - extra: string (optional)
    - has_2fa: boolean (required)

    Response
    --------
    on success::

        { "entry_id": number }

    on error::

        { "status": "error", "msg": string }

    Status codes
    ------------
    - 200: success
    - 400: various input validation errors
    - 401: not authenticated
    - 403: CSRF check failed
    """
    # token has been spent here
    dec_entry = {
        "account": request_data["account"],
        "username": request_data["username"],
        "password": request_data["password"],
        "extra": (request_data["extra"] or ""),
        "has_2fa": request_data["has_2fa"]
    }
    entry = backend.insert_entry_for_user(
        db_session=db.session,
        dec_entry=dec_entry,
        user_id=session["user_id"],
        user_key=session["password"]
    )
    code = 200
    data = {"entry_id": entry.id}
    return write_json(code, data)


@api_v1.route("/api/v1/entries/<int:entry_id>", methods=["PATCH", "PUT"])
@requires_json_auth
@requires_csrf_check
@requires_json_form_validation(NewEntryForm)
def api_v1_update_entry(request_data: NewEntryForm, entry_id: int):
    """Update the specified entry.

    Arguments
    ---------
    - account: string (required)
    - username: string (required)
    - password: string (required)
    - extra: string (optional)
    - has_2fa: boolean (required)

    Response
    --------
    Success or error message::

        { "status": "success"|"error", "msg": string }

    Status codes
    ------------
    - 200: success
    - 400: various input validation errors
    - 401: not authenticated
    - 403: CSRF check failed
    """
    code = 200
    data = {}  # type: dict
    try:
        backend.edit_entry(
            db.session,
            entry_id,
            session["password"],
            request_data,
            session["user_id"]
        )
        code, data = json_success(
            "successfully edited account %s" % escape(request_data["account"])
        )
    except NoResultFound:
        code, data = json_error(400, "no such entry")
    except AssertionError:
        code, data = json_error(400, "the given entry does not belong to you")
    return write_json(code, data)


@api_v1.route("/api/v1/entries/nuclear", methods=["POST"])
@api_v1.route("/api/v1/entries", methods=["DELETE"])
@requires_json_auth
@requires_csrf_check
def api_v1_nuke_entries():
    """Delete <b>all</b> entries for the logged-in user.

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
    - 403: CSRF token validation failed
    """
    user = db.session.query(User).filter_by(id=session["user_id"]).one()
    backend.delete_all_entries(db.session, user)
    code, data = json_success("Deleted all entries")
    return write_json(code, data)


#  -------------- ENTRIES END


@api_v1.route("/api/v1/user/signup", methods=["POST"])
@requires_json_form_validation(SignupForm)
def api_v1_signup(request_data: SignupForm):
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
            token.user_id = user.id
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
            code, data = json_error(
                400,
                "an account with this email address already exists"
            )
        else:
            code, data = json_error(
                400,
                "This account has already been created. Check your inbox for a confirmation email."
            )
    return write_json(code, data)


@api_v1.route("/api/v1/user/activate", methods=["POST"])
@requires_json_form_validation(ActivateAccountForm)
def api_v1_confirm_signup(request_data: ActivateAccountForm):
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


@api_v1.route("/api/v1/user/recover/confirm", methods=["POST"])
@requires_json_form_validation(ConfirmRecoverPasswordForm)
def api_v1_recover_password_confirm(request_data: ConfirmRecoverPasswordForm):
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
def api_v1_delete_user(request_data: DeleteUserForm):
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


@api_v1.route("/api/v1/user/password", methods=["PATCH", "PUT"])
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
