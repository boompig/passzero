from datetime import datetime, timedelta
from io import BytesIO

from flask import Blueprint, abort, escape, request, send_file, session
from sqlalchemy.orm.exc import NoResultFound

from passzero import backend, change_password
from passzero.api_utils import (generate_csrf_token, json_error, json_internal_error,
                                json_success, requires_csrf_check, requires_json_auth,
                                requires_json_form_validation, write_json)
from passzero.forms import (ActivateAccountForm,
                            DeleteUserForm, LoginForm,
                            NewDocumentForm,
                            SignupForm, UpdatePasswordForm, UpdatePreferencesForm)
from passzero.models import ApiStats, AuthToken, EncryptedDocument, User, db

api_v1 = Blueprint("api_v1", __name__)


class UserNotActiveException(Exception):
    pass


class TokenExpiredException(Exception):
    pass


@api_v1.after_app_request
def log_api_stats(response):
    now = datetime.now()
    day = now.isoformat().split("T")[0]
    path = request.path
    week_of_year = now.isocalendar().week
    # find the first antecedent Monday (note that Monday is weekday == 0)
    t = now
    day_of_week = t.weekday()
    while day_of_week > 0:
        t -= timedelta(days=1)
        day_of_week = t.weekday()
    day = t.isoformat().split("T")[0]

    stats = db.session.query(ApiStats).filter_by(
        path=path, day=day).one_or_none()
    if stats is None:
        stats = ApiStats(
            path=path,
            day=day,
            count=1,
            week_of_year=week_of_year,
        )
    else:
        stats.count += 1
    db.session.add(stats)
    db.session.commit()
    return response


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


@api_v1.route("/api/v1/docs/<int:document_id>", methods=["PUT", "PATCH"])
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
        backend.create_new_account(
            db_session=db.session,
            email=request_data["email"],
            password=request_data["password"],
        )
        code, data = json_success(
            "Successfully created account with email %s" % request_data['email']
        )
        return write_json(code, data)
    except backend.UserExistsError as err:
        code, data = json_error(400, str(err))
        return write_json(code, data)
    except backend.EmailSendError:
        code, data = json_internal_error("failed to send email")
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
        backend.delete_account(db.session, user)
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
