from flask import Flask, render_template, redirect, session, request, url_for, escape, flash, Response, make_response
from flask_sslify import SSLify
from flask.ext.compress import Compress
from flask.ext.sqlalchemy import SQLAlchemy
import json
import os
from sqlalchemy.orm.exc import NoResultFound
from werkzeug.contrib.fixers import ProxyFix

# some helpers
import config
from crypto_utils import encrypt_password, decrypt_password, pad_key, get_hashed_password, get_salt, random_hex
from datastore_postgres import db_init, get_user_salt, check_login, db_get_entries, save_edit_entry, db_save_entry, db_export, db_delete_entry, db_create_account, db_update_password, db_confirm_signup, db_get_account
from forms import LoginForm, SignupForm, NewEntryForm, UpdatePasswordForm, RecoverPasswordForm, ConfirmRecoverPasswordForm
from mailgun import send_confirmation_email, send_recovery_email


if os.path.exists("my_env.py"):
    from my_env import setup_env
    setup_env()

compress = Compress()
app = Flask(__name__, static_url_path="")
compress.init_app(app)
app.config.from_object(config)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ['DATABASE_URL']
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

    def random_token(self):
        self.token = random_hex(app.config['TOKEN_SIZE'])

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

    def __repr__(self):
        return "<Entry(account=%s, username=%s, password=%s, padding=%s, user_id=%d)>" % (self.account, self.username, self.password, self.padding, self.user_id)

def check_auth():
    """Return True iff user_id and password are in session."""
    return 'user_id' in session and 'password' in session


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


def json_success(msg):
    """Return tuple of (code, JSON data)"""
    return (200, {
        "status": "success",
        "msg": msg
    })


def json_internal_error(msg):
    """Return tuple of (code, JSON data)"""
    return json_error(500, msg)


@app.route("/entries/<int:entry_id>", methods=["DELETE"])
def delete_entry_api(entry_id):
    """Print 1 on success and 0 on failure"""
    if check_auth():
        result = db_delete_entry(session['user_id'], entry_id)
        if result:
            code, data = json_success("successfully deleted entry with ID %d" % entry_id)
        else:
            code, data = json_error(500, "failed to delete entry with ID %d" % entry_id)
    else:
        code, data = json_noauth()

    return write_json(code, data)


@app.route("/", methods=["GET"])
def index():
    if check_auth():
        return render_template("index.html",
            logged_in=True,
            email=session['email']
        )
    else:
        return render_template("landing.html")


@app.route("/entries/post_delete/<account_name>", methods=["GET"])
def post_delete(account_name):
    flash("Successfully deleted account %s" % escape(account_name))
    return redirect(url_for("view_entries"))


@app.route("/done_login", methods=["GET"])
def post_login():
    flash("Successfully logged in as %s" % escape(session['email']))
    return redirect(url_for("index"))


@app.route("/login", methods=["POST"])
def login_api():
    form = LoginForm(request.form)
    if form.validate():
        try:
            user = db.session.query(User).filter_by(email=request.form['email']).one()
            if user.authenticate(request.form['password']):
                session['email'] = user.email
                session['password'] = request.form['password']
                session['user_id'] = user.id

                code, data = json_success("successfully logged in as %s" % escape(session['email']))
            else:
                code, data = json_error(401, "Either the email or password is incorrect")
        except NoResultFound:
            code, data = json_error(401, "There is not account with that email")
    else:
        code, data = json_form_validation_error(form.errors)

    return write_json(code, data)

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

    flash("Successfully logged out")
    return redirect(url_for("login"))


@app.route("/entries/new", methods=["GET"])
def new_entry_view():
    if not check_auth():
        return redirect(url_for("login"))
    return render_template("new.html", error=None)


@app.route("/entries/new", methods=["POST"])
def new_entry_api():
    form = NewEntryForm(request.form)
    if form.validate():
        if check_auth():
            code = 200
        else:
            code, data = json_noauth()
    else:
        code, data = json_form_validation_error(form.errors)

    if code == 200:
        padding = pad_key(session['password'])
        enc_pass = encrypt_password(session['password'] + padding, request.form['password'])

        status = db_save_entry(
            session['user_id'],
            request.form['account'],
            request.form['username'],
            enc_pass,
            padding
        )

        if status:
            code, data = json_success("successfully added account %s" % escape(request.form['account']))
        else:
            code, data = json_internal_error("internal server error")

    return write_json(code, data)


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
    obj = []
    for row in entries:
        hex_ciphertext = row["password"]
        padding = row["padding"]
        password = decrypt_password(key + padding, hex_ciphertext)
        obj.append({
            "id": row["id"],
            "account": row["account"],
            "username": row["username"],
            "password": password
        })
    return obj

@app.route("/view", methods=["GET"])
def view_entries():
    if not check_auth():
        #TODO flash some kind of error here
        return redirect(url_for("login"))

    entries = db_get_entries(session['user_id'])
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
            token = random_hex(app.config['TOKEN_SIZE'])
            if send_confirmation_email(request.form['email'], token):
                if db_create_account(request.form['email'], password_hash, salt, token):
                    code, data = json_success(
                        "Successfully created account with email %s" % request.form['email']
                    )
                else:
                    code, data = json_error(409, "an account with this email address already exists")
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
    if "token" in request.args:
        token = request.args['token']
        if db_confirm_signup(token):
            return redirect(url_for("post_confirm_signup"))
        else:
            #TODO invalid request
            return "invalid token"
    else:
        #TODO invalid request
        return "token required"


@app.route("/advanced/export", methods=["GET"])
def export_entries():
    if not check_auth():
        #TODO
        return "unauthorized"

    export_contents = db_export(session['user_id'])
    response = make_response(export_contents)
    response.headers["Content-Disposition"] = "attachment; filename=passzero_dump.csv"
    return response


@app.route("/advanced/done_export")
def post_export():
    flash("database successfully dumped to file %s" % DUMP_FILE)
    return redirect("/advanced")


@app.route("/entries/<entry_id>", methods=["POST"])
def edit_entry_api(entry_id):
    code = 200
    data = {}
    if not check_auth():
        code, data = json_noauth()

    form = NewEntryForm(request.form)
    if not form.validate():
        code, data = json_form_validation_error(form.errors)
    else:
        padding = pad_key(session['password'])
        enc_pass = encrypt_password(session['password'] + padding, request.form['password'])

        status = save_edit_entry(
            session['user_id'],
            entry_id,
            request.form['account'],
            request.form['username'],
            enc_pass,
            padding
        )
        if status:
            code, data = json_success(
                "successfully edited account %s" % escape(request.form["account"])
            )
        else:
            code, data = json_internal_error("internal server error")

    return write_json(code, data)


@app.route("/edit/<entry_id>", methods=["GET"])
def edit_entry(entry_id):
    if not check_auth():
        return redirect(url_for("login"))
    if not entry_id.isdigit():
        return "entry ID must be an integer"

    entry_id = int(str(entry_id))
    entries = db_get_entries(session['user_id'])
    dec_entries = decrypt_entries(entries, session['password'])

    fe = [e for e in dec_entries if e["id"] == entry_id]
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


@app.route("/advanced/password", methods=["UPDATE"])
def update_password_api():
    if check_auth():
        form = UpdatePasswordForm(request.form)
        if form.validate():
            entries = db_get_entries(session['user_id'])
            dec_entries = decrypt_entries(entries, session['password'])
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
        else:
            code, data = json_form_validation_error(form.errors)
    else:
        code, data = json_noauth()

    return write_json(code, data)


@app.route("/recover")
def recover_password():
    return render_template("recover.html")


@app.route("/recover/confirm")
def recover_password_confirm():
    try:
        token = request.args['token']
        token_obj = db.session.query(AuthToken).filter_by(token=token).one()
        return render_template("recover.html", confirm=True)
    except NoResultFound:
        return "Token is invalid"
    except KeyError:
        return "Token is mandatory"

@app.route("/recover/confirm", methods=["POST"])
def recover_password_confirm_api():
    form = ConfirmRecoverPasswordForm(request.form)
    if form.validate():
        token = db.session.query(AuthToken).filter_by(token=request.form['token']).one()
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

@app.route("/entries/nuclear", methods=["POST"])
def nuke_entries_api():
    if check_auth():
        entries = db.session.query(Entry).filter_by(user_id=session['user_id']).all()
        for entry in entries:
            db.session.delete(entry)
        db.session.commit()
        code, data = json_success("Deleted all entries")
    else:
        code, data = json_noauth()
    return write_json(code, data)

@app.route("/recover", methods=["POST"])
def recover_password_api():
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
