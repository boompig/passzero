from datetime import datetime
from flask import Flask, render_template, redirect, session, request, url_for, escape, flash, Response, make_response, abort
from flask_sslify import SSLify
from flask.ext.compress import Compress
from flask.ext.sqlalchemy import SQLAlchemy
from functools import wraps
import json
import os
from sqlalchemy.orm.exc import NoResultFound
from sqlalchemy.sql import func, asc
from werkzeug.contrib.fixers import ProxyFix

# some helpers
import config
from crypto_utils import encrypt_password, decrypt_password, pad_key, get_hashed_password, get_salt, random_hex, encrypt_field, decrypt_field
from datastore_postgres import db_init, db_export, db_update_password
from forms import LoginForm, SignupForm, NewEntryForm, UpdatePasswordForm, RecoverPasswordForm, ConfirmRecoverPasswordForm
from mailgun import send_confirmation_email, send_recovery_email


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
db = SQLAlchemy(app)


class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, db.Sequence("users_id_seq"), primary_key=True)
    email = db.Column(db.String, unique=True)
    password = db.Column(db.String, nullable=False)
    salt = db.Column(db.String(32), nullable=False)
    active = db.Column(db.Boolean, nullable=False, default=False)
    last_login = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def authenticate(self, form_password):
        """Return True on success, False on failure."""
        hashed_password = get_hashed_password(form_password, self.salt)
        return self.password == hashed_password

    def change_password(self, new_password):
        hashed_password = get_hashed_password(new_password, self.salt)
        self.password = hashed_password

    def __repr__(self):
        return "<User(email=%s, password=%s, salt=%s, active=%s)>" % (self.email, self.password, self.salt, str(self.active))


class AuthToken(db.Model):
    __tablename__ = "auth_tokens"
    id = db.Column(db.Integer, db.Sequence("entries_id_seq"), primary_key=True)
    user_id = db.Column(db.String, db.ForeignKey("users.id"), nullable=False)
    token = db.Column(db.String, nullable=False)
    issue_time = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    # in seconds
    MAX_AGE = 15 * 60

    def random_token(self):
        self.token = random_hex(app.config['TOKEN_SIZE'])

    def is_expired(self):
        delta = datetime.utcnow() - self.issue_time
        return delta.seconds > self.MAX_AGE

    def __repr__(self):
        return "<AuthToken(user_id=%d, token=%s)>" % (self.user_id, self.token)


class Entry(db.Model):
    __tablename__ = "entries"
    id = db.Column(db.Integer, db.Sequence("entries_id_seq"), primary_key=True)
    user_id = db.Column(db.String, db.ForeignKey("users.id"), nullable=False)
    account = db.Column(db.String, nullable=False)
    username = db.Column(db.String, nullable=False)
    password = db.Column(db.String, nullable=False)
    padding = db.Column(db.String, nullable=False)
    extra = db.Column(db.String)

    def __repr__(self):
        return "<Entry(account=%s, username=%s, password=%s, padding=%s, user_id=%d)>" % (self.account, self.username, self.password, self.padding, self.user_id)

    def decrypt(self, key):
        """Return a dictionary mapping fields to their decrypted values."""
        dec_password = decrypt_password(key + self.padding, self.password)
        if self.extra:
            try:
                dec_extra = decrypt_field(key, self.padding, self.extra)
            except TypeError:
                dec_extra = self.extra
        else:
            dec_extra = ""
        try:
            dec_username = decrypt_field(key, self.padding, self.username)
        except TypeError:
            dec_username = self.username
        return { "password": dec_password, "extra": dec_extra, "username": dec_username }

    def encrypt(self, key, salt, obj):
        self.password = encrypt_password(key + salt, obj["password"])
        self.extra = encrypt_field(key, salt, obj["extra"])
        self.username = encrypt_field(key, salt, obj["username"])


def get_entries():
    return db.session.query(Entry).filter_by(
            user_id=session['user_id']).order_by(asc(func.lower(Entry.account))).all()


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
    if request.method == "POST" or request.method == "UPDATE":
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

@app.route("/api/login", methods=["POST"])
@app.route("/login", methods=["POST"])
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
    form = LoginForm(request.form)
    if form.validate():
        try:
            user = db.session.query(User).filter_by(email=request.form["email"]).one()
            if user.authenticate(request.form["password"]):
                session["email"] = user.email
                session["password"] = request.form["password"]
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
    else:
        code, data = json_form_validation_error(form.errors)
    return write_json(code, data)


@app.route("/api/entries", methods=["GET"])
@requires_json_auth
def api_get_entries():
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
@app.route("/entries/<int:entry_id>", methods=["DELETE"])
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


@app.route("/entries/new", methods=["POST"])
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
    form = NewEntryForm(request.form)
    if form.validate():
        code = 200
    else:
        code, data = json_form_validation_error(form.errors)

    if code == 200:
        padding = pad_key(session['password'])

        entry = Entry()
        entry.encrypt(session['password'], padding, request.form)

        entry.user_id = session['user_id']
        entry.account = request.form['account']
        entry.padding = padding

        db.session.add(entry)
        db.session.commit()
        code, data = json_success("successfully added account %s" % escape(request.form['account']))

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
        obj["account"] = row.account
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


@app.route("/signup", methods=["POST"])
def signup_api():
    form = SignupForm(request.form)
    if form.validate():
        try:
            user = db.session.query(User).filter_by(email=request.form['email']).one()
        except NoResultFound:
            salt = get_salt(app.config['SALT_SIZE'])
            password_hash = get_hashed_password(request.form['password'], salt)
            token = AuthToken()
            token.random_token()
            if send_confirmation_email(request.form['email'], token.token):
                user = User()
                user.email = request.form['email']
                user.password = password_hash
                user.salt = salt
                user.active = False

                # necessary to get user ID
                db.session.add(user)
                db.session.commit()

                token.user_id = user.id;

                # now add token
                db.session.add(token)
                db.session.commit()
                code, data = json_success(
                    "Successfully created account with email %s" % request.form['email']
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

            # set the user as active
            user.active = True
            db.session.add(user)
            db.session.commit()
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

    export_contents = db_export(session['user_id'])
    response = make_response(export_contents)
    response.headers["Content-Disposition"] = ("attachment; filename=%s" %\
            app.config['DUMP_FILE'])
    return response


@app.route("/advanced/done_export")
def post_export():
    flash("database successfully dumped to file %s" % app.config['DUMP_FILE'])
    return redirect("/advanced")


@app.route("/api/entries/<int:entry_id>", methods=["POST"])
@app.route("/entries/<int:entry_id>", methods=["POST"])
@requires_json_auth
@requires_csrf_check
def edit_entry_api(entry_id):
    code = 200
    data = {}
    form = NewEntryForm(request.form)
    if not form.validate():
        code, data = json_form_validation_error(form.errors)
    else:
        try:
            entry = db.session.query(Entry).filter_by(id=entry_id).one()
            assert entry.user_id == session['user_id']
            padding = pad_key(session['password'])
            entry.encrypt(session["password"], padding, request.form)

            entry.account = request.form['account']
            entry.padding = padding

            db.session.add(entry)
            db.session.commit()
            code, data = json_success(
                "successfully edited account %s" % escape(request.form["account"])
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
        dec_entries = decrypt_entries(entries, session['password'])
    except ValueError:
        msg = "Error decrypting entries. This means the old password is most likely incorrect"
        code, data = json_error(500, msg)
        return write_json(code, data)
    status = db_update_password(
        session['user_id'],
        session['email'],
        request.form['old_password'],
        request.form['new_password'],
        dec_entries
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
    entries = get_entries()
    for entry in entries:
        db.session.delete(entry)
    db.session.commit()
    code, data = json_success("Deleted all entries")
    return write_json(code, data)


@app.route("/recover", methods=["POST"])
def recover_password_api():
    """This method sends a recovery email to the user's email address.
    It does not require any authentication."""
    form = RecoverPasswordForm(request.form)
    if form.validate():
        try:
            user = db.session.query(User).filter_by(email=request.form['email']).one()
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
    db_init()

    if DEBUG:
        app.debug = True
        app.run(port=app.config['PORT'], ssl_context=("server.crt", "server.key"))
    else:
        app.debug = False
        app.run(host='0.0.0.0', port=app.config['PORT'])
