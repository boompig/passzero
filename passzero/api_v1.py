from datetime import datetime
from flask import Blueprint, session, request, escape
from .api_utils import requires_json_auth, requires_csrf_check, generate_csrf_token, write_json, json_form_validation_error, json_success, json_error, json_internal_error
from .change_password import insert_new_entry, change_password
from .forms import LoginForm, NewEntryForm, SignupForm, RecoverPasswordForm, ConfirmRecoverPasswordForm, UpdatePasswordForm
from .backend import get_account_with_email, get_entries, decrypt_entries,\
        encrypt_entry, create_inactive_user, delete_all_entries
from .models import db, Entry, AuthToken, User
from .mailgun import send_confirmation_email, send_recovery_email
from sqlalchemy.orm.exc import NoResultFound


api_v1 = Blueprint("api_v1", __name__)

@api_v1.route("/api/csrf_token", methods=["GET"])
@api_v1.route("/api/v1/csrf_token", methods=["GET"])
def api_get_csrf_token():
    token = generate_csrf_token()
    return write_json(200, token)


@api_v1.route("/api/logout", methods=["POST"])
@api_v1.route("/api/v1/logout", methods=["POST"])
def api_logout():
    if 'email' in session:
        session.pop("email")
    if 'password' in session:
        session.pop("password")
    if 'user_id' in session:
        session.pop("user_id")
    code, data = json_success("Successfully logged out")
    return write_json(code, data)


@api_v1.route("/api/login", methods=["POST"])
@api_v1.route("/api/v1/login", methods=["POST"])
def api_login():
    """Try to log in using JSON post data.
    Respond with JSON data and set HTTP status code.
    On success:
        - fetch user from database
        - set session cookies
        - update last login info in database
        - return 200 code and success msg in JSON
    On error:
        - return 4xx code and error msg in JSON
    """
    request_data = request.get_json()
    form = LoginForm(data=request_data)
    if form.validate():
        try:
            user = get_account_with_email(db.session, request_data["email"])
            assert(user.active)
            if user.authenticate(request_data["password"]):
                session["email"] = user.email
                session["password"] = request_data["password"]
                session["user_id"] = user.id
                generate_csrf_token()
                # write into last_login
                user.last_login = datetime.utcnow()
                db.session.add(user)
                db.session.commit()
                # craft message to return to user
                msg = "successfully logged in as {email}".format(
                    email = escape(session["email"])
                )
                code, data = json_success(msg)
            else:
                code, data = json_error(401, "Either the email or password is incorrect")
        except NoResultFound:
            code, data = json_error(401, "There is no account with that email")
        except AssertionError:
            code, data = json_error(401,
                "The account has not been activated. Check your email!")
    else:
        code, data = json_form_validation_error(form.errors)
    return write_json(code, data)


@api_v1.route("/api/entries", methods=["GET"])
@api_v1.route("/api/v1/entries", methods=["GET"])
@requires_json_auth
def get_entries_api():
    """Get entries of logged-in user.
    Respond with JSON data corresponding to entries, or error msg. Set HTTP status code.
    On success:
        - read all entries and decrypt them
        - write them out as massive JSON array
        - set status code 200
    On error:
        - set status code 4xx
    """
    code = 200
    entries = get_entries(db.session, session["user_id"])
    dec_entries = decrypt_entries(entries, session['password'])
    data = dec_entries
    return write_json(code, data)


@api_v1.route("/api/entries/<int:entry_id>", methods=["DELETE"])
@api_v1.route("/api/v1/entries/<int:entry_id>", methods=["DELETE"])
@requires_json_auth
@requires_csrf_check
def delete_entry_api(entry_id):
    """Delete the entry with the given ID. Return JSON.
    Provide success/failure via HTTP status code."""
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


@api_v1.route("/api/entries/new", methods=["POST"])
@api_v1.route("/api/v1/entries/new", methods=["POST"])
@requires_json_auth
@requires_csrf_check
def new_entry_api():
    """Create a new entry for the logged-in user.
    POST parameters:
        - account (required)
        - password (required)
        - confirm_password (required)
        - extra (optional)
    Respond with JSON message on success, and 4xx codes and message on failure.
        - 401: not authenticated
        - 400: error in POST parameters
        - 403: CSRF check failed
        - 200: success
    """
    request_data = request.get_json()
    form = NewEntryForm(data=request_data)
    if form.validate():
        code = 200
    else:
        code, data = json_form_validation_error(form.errors)
    if code == 200:
        dec_entry = {
            "account": request_data["account"],
            "username": request_data["username"],
            "password": request_data["password"],
            "extra": (request_data["extra"] or "")
        }
        entry = encrypt_entry(dec_entry, session["password"])
        insert_new_entry(db.session, entry, session["user_id"])
        db.session.commit()
        code = 200
        data = { "entry_id": entry.id }
    return write_json(code, data)


@api_v1.route("/api/signup", methods=["POST"])
@api_v1.route("/api/v1/signup", methods=["POST"])
def signup_api():
    request_data = request.get_json()
    form = SignupForm(data=request_data)
    if form.validate():
        try:
            user = get_account_with_email(db.session, request_data["email"])
        except NoResultFound:
            token = AuthToken()
            token.random_token()
            if send_confirmation_email(request_data["email"], token.token):
                user = create_inactive_user(
                    db.session,
                    request_data["email"],
                    request_data["password"]
                )
                token.user_id = user.id;
                # now add token
                db.session.add(token)
                db.session.commit()
                code, data = json_success(
                    "Successfully created account with email %s" % request_data['email']
                )
            else:
                code, data = json_internal_error("failed to send email")
        else:
            if user.active:
                code, data = json_error(400, "an account with this email address already exists")
            else:
                code, data = json_error(400, "This account has already been created. Check your inbox for a confirmation email.")
    else:
        code, data = json_form_validation_error(form.errors)
    return write_json(code, data)


@api_v1.route("/api/recover", methods=["POST"])
@api_v1.route("/api/v1/recover", methods=["POST"])
@api_v1.route("/api/v1/user/recover", methods=["POST"])
def recover_password_api():
    """This method sends a recovery email to the user's email address.
    It does not require any authentication."""
    request_data = request.get_json()
    form = RecoverPasswordForm(data=request_data)
    if form.validate():
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
                code, data = json_internal_error("internal server error")
        except NoResultFound:
            code, data = json_error(401, "no such email")
    else:
        code, data = json_form_validation_error(form.errors)
    return write_json(code, data)


@api_v1.route("/api/v1/user/recover/confirm", methods=["POST"])
@api_v1.route("/api/v1/recover/confirm", methods=["POST"])
@api_v1.route("/recover/confirm", methods=["POST"])
def recover_password_confirm_api():
    """This is the API that is hit by a link from an email.
    Check the token that is sent with the email, then nuke all the entries.
    Return JSON. HTTP status codes indicate success or failure.
    """
    form = ConfirmRecoverPasswordForm(request.form)
    if form.validate():
        token = db.session.query(AuthToken).filter_by(token=request.form['token']).one()
        if token.is_expired():
            # delete old token
            db.session.delete(token)
            db.session.commit()
            # return error via JSON
            code, data = json_error(400, "token has expired")
        else:
            user = db.session.query(User).filter_by(id=token.user_id).one()
            # 1) change the user's password
            user.change_password(request.form['password'])
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
    else:
        code, data = json_form_validation_error(form.errors)
    return write_json(code, data)


@api_v1.route("/api/v1/entries/nuclear", methods=["POST"])
@api_v1.route("/api/entries/nuclear", methods=["POST"])
@api_v1.route("/entries/nuclear", methods=["POST"])
@requires_json_auth
@requires_csrf_check
def nuke_entries_api():
    """Delete all entries. Return JSON. Success is measured by HTTP status code.
    Possible values:
        - 401: failed to authenticate
        - 403: CSRF token validation failed
        - 200: success
    """
    user = db.session.query(User).filter_by(id=session["user_id"]).one()
    delete_all_entries(db.session, user)
    code, data = json_success("Deleted all entries")
    return write_json(code, data)


@api_v1.route("/api/v1/entries/<int:entry_id>", methods=["POST"])
@api_v1.route("/api/entries/<int:entry_id>", methods=["POST"])
@api_v1.route("/entries/<int:entry_id>", methods=["POST"])
@requires_json_auth
@requires_csrf_check
def edit_entry_api(entry_id):
    request_data = request.get_json()
    form = NewEntryForm(data=request_data)
    if not form.validate():
        code, data = json_form_validation_error(form.errors)
    else:
        code = 200
        data = {}
        try:
            entry = db.session.query(Entry).filter_by(id=entry_id).one()
            assert entry.user_id == session['user_id']
            dec_entry = {
                "account": request_data["account"],
                "username": request_data["username"],
                "password": request_data["password"],
                "extra": (request_data["extra"] or "")
            }
            # do not add e2 to session, it's just a placeholder
            e2 = encrypt_entry(dec_entry, session["password"])
            entry.account = e2.account
            entry.username = e2.username
            entry.password = e2.password
            entry.extra = e2.extra
            entry.iv = e2.iv
            entry.key_salt = e2.key_salt
            db.session.commit()
            code, data = json_success(
                "successfully edited account %s" % escape(request_data["account"])
            )
        except NoResultFound:
            code, data = json_error(400, "no such entry")
        except AssertionError:
            code, data = json_error(400, "the given entry does not belong to you")
    return write_json(code, data)


@api_v1.route("/api/v1/advanced/password", methods=["UPDATE"])
@api_v1.route("/api/advanced/password", methods=["UPDATE"])
@api_v1.route("/advanced/password", methods=["UPDATE"])
@requires_json_auth
@requires_csrf_check
def update_password_api():
    """Change the master password. Return values are JSON.
    Success is marked by HTTP status code."""
    form = UpdatePasswordForm(request.form)
    if not form.validate():
        code, data = json_form_validation_error(form.errors)
        return write_json(code, data)
    entries = get_entries(db.session, session["user_id"])
    try:
        decrypt_entries(entries, session['password'])
    except ValueError:
        msg = "Error decrypting entries. This means the old password is most likely incorrect"
        code, data = json_error(500, msg)
        return write_json(code, data)
    status = change_password(
        db.session,
        session['user_id'],
        request.form['old_password'],
        request.form['new_password'],
    )
    if status:
        session['password'] = request.form['new_password']
        code, data = json_success("successfully changed password")
    else:
        code, data = json_error(401, "old password is incorrect")
    return write_json(code, data)


