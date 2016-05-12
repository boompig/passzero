from datetime import datetime
from flask import Flask, render_template, redirect, session, request, url_for, escape, flash, Response, make_response, abort
from flask_sslify import SSLify
from flask.ext.compress import Compress
from functools import wraps
import json
import os
from sqlalchemy.orm.exc import NoResultFound
from sqlalchemy.sql import func, asc
from werkzeug.contrib.fixers import ProxyFix

# some helpers
import config
from crypto_utils import get_hashed_password, get_salt, random_hex
from datastore_postgres import db_export
from forms import LoginForm, SignupForm, NewEntryForm, UpdatePasswordForm, RecoverPasswordForm, ConfirmRecoverPasswordForm, NewEncryptedEntryForm
from mailgun import send_confirmation_email, send_recovery_email
from models import db, User, AuthToken, EncryptedEntry, Entry
from utils.change_password import change_password, encrypt_entry, insert_new_entry


def generate_csrf_token():
    """Generate a CSRF token for the session, if not currently set"""
    if "csrf_token" not in session:
        session["csrf_token"] = random_hex(app.config["CSRF_TOKEN_LENGTH"])
    return session["csrf_token"]


if os.path.exists("my_env.py"):
    from my_env import setup_env
    setup_env()

compress = Compress()
app = Flask(__name__, static_url_path="")
compress.init_app(app)
app.config.from_object(config)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ['DATABASE_URL']
app.config['DUMP_FILE'] = "passzero_dump.csv"

# define global callback for CSRF token"""
app.jinja_env.globals["csrf_token"] = generate_csrf_token

if 'FLASK_SECRET_KEY' in os.environ:
    app.secret_key = str(os.environ["FLASK_SECRET_KEY"])
    sslify = SSLify(app, permanent=True)
    DEBUG = False
else:
    sslify = SSLify(app, permanent=True)
    app.secret_key = '64f5abcf8369e362c36a6220128de068'
    DEBUG = True

db.app = app
db.init_app(app)


def get_entries():
    return db.session.query(Entry)\
        .filter_by(user_id=session['user_id'], pinned=False)\
        .order_by(asc(func.lower(Entry.account)))\
        .all()


def check_auth():
    """Return True iff user_id and password are in session."""
    return 'user_id' in session and 'password' in session


def check_csrf(form):
    "Return True iff csrf_token is set in the given form and it matches up with the session"""
    return "csrf_token" in form and form["csrf_token"] == session["csrf_token"]


def json_error(code, msg):
    return (code, {
        "status": "error",
        "msg": msg
    })


def json_noauth():
    """Return tuple of (code, json object)"""
    return json_error(401, "must be logged in to perform this action")


def write_json(code, data):
    """Write JSON response. Code is status code."""
    return Response(
        json.dumps(data),
        status=code,
        mimetype="application/json"
    )


def json_form_validation_error(errors):
    code, data = json_error(400, "Failed to validate form")
    for k, v in dict(errors).iteritems():
        data[k] = v[0]
    return (code, data)


def json_csrf_validation_error():
    code, data = json_error(403, "Failed to validate CSRF token")
    return (code, data)


def json_success(msg):
    """Return tuple of (code, JSON data)"""
    return (200, {
        "status": "success",
        "msg": msg
    })


def json_internal_error(msg):
    """Return tuple of (code, JSON data)"""
    return json_error(500, msg)


def check_all_csrf():
    """Check CSRF token differently depending on the request method"""
    data = request.get_json(silent=True)
    if data:
        return check_csrf(data)
    elif request.method == "POST" or request.method == "UPDATE":
        return check_csrf(request.form)
    elif request.method == "DELETE" or request.method == "GET":
        return check_csrf(request.args)
    else:
        return abort(500)


def requires_json_auth(function):
    """This is a decorator which does authentication for JSON requests.
    If not authenticated, return json_noauth.
    If authenticated, call the function."""
    @wraps(function)
    def inner(*args, **kwargs):
        if check_auth():
            return function(*args, **kwargs)
        else:
            code, data = json_noauth()
            return write_json(code, data)
    return inner


def requires_csrf_check(function):
    """This is a decorator which checks CSRF tokens for JSON requests.
    If not authenticated, return json_csrf_validation_error.
    If authenticated, call the function."""
    @wraps(function)
    def inner(*args, **kwargs):
        if check_all_csrf():
            return function(*args, **kwargs)
        else:
            code, data = json_csrf_validation_error()
            return write_json(code, data)
    return inner


@app.route("/", methods=["GET"])
def index():
    if check_auth():
        return redirect(url_for("view_entries"))
        #return render_template("index.html",
            #logged_in=True,
            #email=session['email']
        #)
    else:
        return render_template("landing.html")


@app.route("/entries/post_delete/<account_name>", methods=["GET"])
def post_delete(account_name):
    flash("Successfully deleted account %s" % escape(account_name))
    return redirect(url_for("view_entries"))


@app.route("/done_login", methods=["GET"])
def post_login():
    flash("Successfully logged in as %s" % escape(session['email']))
    return redirect(url_for("view_entries"))


##################################################
#   API-only, returns JSON
##################################################

##### below: API v1

@app.route("/api/csrf_token", methods=["GET"])
def api_get_csrf_token():
    token = generate_csrf_token()
    return write_json(200, token)


@app.route("/api/logout", methods=["POST"])
def api_logout():
    if 'email' in session:
        session.pop("email")
    if 'password' in session:
        session.pop("password")
    if 'user_id' in session:
        session.pop("user_id")
    code, data = json_success("Successfully logged out")
    return write_json(code, data)


@app.route("/api/login", methods=["POST"])
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
            user = get_account_with_email(request_data["email"])
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


@app.route("/api/entries", methods=["GET"])
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
    entries = get_entries()
    dec_entries = decrypt_entries(entries, session['password'])
    data = dec_entries
    return write_json(code, data)


@app.route("/api/entries/<int:entry_id>", methods=["DELETE"])
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


@app.route("/api/entries/new", methods=["POST"])
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


@app.route("/api/signup", methods=["POST"])
def signup_api():
    request_data = request.get_json()
    form = SignupForm(data=request_data)
    if form.validate():
        try:
            user = get_account_with_email(request_data["email"])
        except NoResultFound:
            token = AuthToken()
            token.random_token()
            if send_confirmation_email(request_data["email"], token.token):
                user = create_inactive_account(
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

### below: API v2

@app.route("/api/v2/entries", methods=["POST"])
@app.route("/api/entries/cse", methods=["POST"])
@requires_json_auth
@requires_csrf_check
def api_new_entry():
    request_data = request.get_json()
    form = NewEncryptedEntryForm(data=request_data)
    if form.validate():
        enc_entry = EncryptedEntry()
        enc_entry.account = request_data["account"]
        enc_entry.username = request_data["username"]
        enc_entry.password = request_data["password"]
        enc_entry.extra = request_data["extra"]
        enc_entry.key_salt = request_data["key_salt"]
        enc_entry.iv = request_data["iv"]
        enc_entry.user_id = session["user_id"]
        db.session.add(enc_entry)
        db.session.commit()
        result_data = { "entry_id": enc_entry.id }
        code = 200
    else:
        code, result_data = json_form_validation_error(form.errors)
    return write_json(code, result_data)


@app.route("/api/v2/entries", methods=["GET"])
@requires_json_auth
def api_get_entries():
    entries = db.session.query(EncryptedEntry).filter_by(
            user_id=session['user_id']).all()
    l = [entry.to_json() for entry in entries]
    return write_json(200, l)


@app.route("/api/v2/entries/<int:entry_id>", methods=["DELETE"])
@requires_json_auth
@requires_csrf_check
def api_delete_entry(entry_id):
    try:
        entry = db.session.query(EncryptedEntry).filter_by(id=entry_id).one()
        assert entry.user_id == session['user_id']
        db.session.delete(entry)
        db.session.commit()
        code, data = json_success("successfully deleted entry with ID %d" % entry_id)
    except NoResultFound:
        code, data = json_error(400, "no such entry")
    except AssertionError:
        code, data = json_error(400, "the given entry does not belong to you")
    return write_json(code, data)


# -----^ API functions ^------
##################################################


@app.route("/login", methods=["GET"])
def login():
    return render_template("login.html", login=True, error=None)


@app.route("/logout", methods=["GET"])
def logout():
    if 'email' in session:
        session.pop("email")
    if 'password' in session:
        session.pop("password")
    if 'user_id' in session:
        session.pop("user_id")

    #flash("Successfully logged out")
    return redirect(url_for("login"))


@app.route("/entries/new", methods=["GET"])
def new_entry_view():
    if not check_auth():
        return redirect(url_for("login"))
    return render_template("new.html", error=None)


@app.route("/done_signup/<email>", methods=["GET"])
def post_signup(email):
    flash("Successfully created account with email %s. A confirmation email was sent to this address." % escape(email))
    return redirect(url_for("login"))


@app.route("/entries/done_edit/<account_name>")
def post_edit(account_name):
    flash("Successfully changed entry for account %s" % escape(account_name))
    return redirect(url_for("view_entries"))


@app.route("/entries/done_new/<account_name>")
def post_create(account_name):
    flash("Successfully created entry for account %s" % escape(account_name))
    return redirect(url_for("view_entries"))


def decrypt_entries(entries, key):
    """Return a list of objects representing the decrypted entries"""
    arr = []
    for row in entries:
        obj = row.decrypt(key)
        obj["id"] = row.id
        arr.append(obj)
    return arr


@app.route("/view", methods=["GET"])
def view_entries():
    if not check_auth():
        #TODO flash some kind of error here
        return redirect(url_for("login"))

    entries = get_entries()
    dec_entries = decrypt_entries(entries, session['password'])
    return render_template("entries.html", entries=dec_entries)


def create_inactive_account(email, password):
    """Create an account which has not been activated.
    Return the user object (model)"""
    salt = get_salt(app.config['SALT_SIZE'])
    password_hash = get_hashed_password(password, salt)
    user = User()
    user.email = email
    user.password = password_hash
    user.salt = salt
    user.active = False
    # necessary to get user ID
    db.session.add(user)
    db.session.commit()
    return user


def activate_account(user):
    """Set the user to active and commit changes"""
    user.active = True
    db.session.add(user)
    db.session.commit()


def delete_all_encrypted_entries(user):
    """Delete all encrypted entries for this user from the database."""
    entries = db.session.query(EncryptedEntry).filter_by(user_id=user.id).all()
    try:
        for entry in entries:
            db.session.delete(entry)
        db.session.commit()
    except:
        session.rollback()
        raise


def delete_all_entries(user):
    entries = db.session.query(Entry).filter_by(user_id=user.id).all()
    for entry in entries:
        db.session.delete(entry)
    db.session.commit()


def delete_all_auth_tokens(user):
    auth_tokens = db.session.query(AuthToken).filter_by(user_id=user.id).all()
    for token in auth_tokens:
        db.session.delete(token)
    db.session.commit()


def delete_account(user):
    """Delete the given user from the database."""
    db.session.delete(user)
    db.session.commit()


def get_account_with_email(email):
     return db.session.query(User).filter_by(email=email).one()


@app.route("/signup", methods=["GET"])
def signup():
    error = None
    #flash("Successfully created account with email %s" % request.form['email'])
    return render_template("login.html", login=False, error=error)


@app.route("/signup/post_confirm")
def post_confirm_signup():
    flash("Successfully signed up! Login with your newly created account")
    return redirect(url_for("login"))


@app.route("/signup/confirm")
def confirm_signup():
    try:
        token = request.args['token']
        token_obj = db.session.query(AuthToken).filter_by(token=token).one()
        if token_obj.is_expired():
            flash("Token has expired")
            # delete old token from database
            db.session.delete(token_obj)
            db.session.commit()
            return redirect(url_for("signup"))
        else:
            # token deleted when password changed
            db.session.delete(token_obj)

            user = db.session.query(User).filter_by(id=token_obj.user_id).one()
            activate_account(user)
            return redirect(url_for("post_confirm_signup"))
    except NoResultFound:
        flash("Token is invalid")
        return redirect(url_for("signup"))
    except KeyError:
        flash("Token is mandatory")
        return redirect(url_for("signup"))


@app.route("/advanced/export", methods=["GET"])
def export_entries():
    if not check_auth():
        #TODO
        return "unauthorized"
    export_contents = db_export(db.session, session['user_id'])
    if export_contents:
        response = make_response(export_contents)
        response.headers["Content-Disposition"] = ("attachment; filename=%s" %\
                app.config['DUMP_FILE'])
        return response
    else:
        return "failed to export table - internal error"


@app.route("/advanced/done_export")
def post_export():
    flash("database successfully dumped to file %s" % app.config['DUMP_FILE'])
    return redirect("/advanced")


@app.route("/api/entries/<int:entry_id>", methods=["POST"])
@app.route("/entries/<int:entry_id>", methods=["POST"])
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


@app.route("/edit/<int:entry_id>", methods=["GET"])
def edit_entry(entry_id):
    if not check_auth():
        return redirect(url_for("login"))
    entries = get_entries()
    my_entries = [e for e in entries if e.id == entry_id]
    fe = decrypt_entries(my_entries, session['password'])
    if len(fe) == 0:
        #TODO flash error msg about invalid ID here
        return redirect(url_for("login"))
    else:
        return render_template("new.html", e_id=entry_id, entry=fe[0], error=None)


@app.route("/advanced")
def advanced():
    if check_auth():
        return render_template("advanced.html")
    else:
        return redirect(url_for("login"))


@app.route("/api/advanced/password", methods=["UPDATE"])
@app.route("/advanced/password", methods=["UPDATE"])
@requires_json_auth
@requires_csrf_check
def update_password_api():
    """Change the master password. Return values are JSON.
    Success is marked by HTTP status code."""
    form = UpdatePasswordForm(request.form)
    if not form.validate():
        code, data = json_form_validation_error(form.errors)
        return write_json(code, data)

    entries = get_entries()
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


@app.route("/recover")
def recover_password():
    return render_template("recover.html")


@app.route("/recover/confirm")
def recover_password_confirm():
    try:
        token = request.args['token']
        token_obj = db.session.query(AuthToken).filter_by(token=token).one()
        if token_obj.is_expired():
            flash("Token has expired")
            # delete old token from database
            db.session.delete(token_obj)
            db.session.commit()
            return redirect(url_for("recover_password"))
        else:
            # token deleted when password changed
            return render_template("recover.html", confirm=True)
    except NoResultFound:
        flash("Token is invalid")
        return redirect(url_for("recover_password"))
    except KeyError:
        flash("Token is mandatory")
        return redirect(url_for("recover_password"))


@app.route("/recover/confirm", methods=["POST"])
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

@app.route("/api/entries/nuclear", methods=["POST"])
@app.route("/entries/nuclear", methods=["POST"])
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
    delete_all_entries(user)
    code, data = json_success("Deleted all entries")
    return write_json(code, data)


@app.route("/api/recover", methods=["POST"])
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


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/version")
def get_version():
    return app.config['BUILD_ID']


app.wsgi_app = ProxyFix(app.wsgi_app)

if __name__ == "__main__":
    db.create_all()

    if DEBUG:
        app.debug = True
        app.run(port=app.config['PORT'], ssl_context=("server.crt", "server.key"))
    else:
        app.debug = False
        app.run(host='0.0.0.0', port=app.config['PORT'])
