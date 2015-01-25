from flask import Flask, render_template, redirect, session, request, url_for, escape, flash, Response
from flask_sslify import SSLify
from werkzeug.contrib.fixers import ProxyFix
import json
import os

# some helpers
from crypto_utils import encrypt_password, decrypt_password, pad_key, get_hashed_password, get_salt
#from datastore_sqlite3 import db_init, get_user_salt, check_login, db_get_entries, save_edit_entry, save_entry, db_export, db_delete_entry, db_create_account
from datastore_postgres import db_init, get_user_salt, check_login, db_get_entries, save_edit_entry, db_save_entry, db_export, db_delete_entry, db_create_account, db_update_password

from forms import SignupForm, NewEntryForm, UpdatePasswordForm


SALT_SIZE = 32
DUMP_FILE = "dump.sql"
PORT = 5050
app = Flask(__name__, static_url_path="")
if 'FLASK_SECRET_KEY' in os.environ:
    app.secret_key = str(os.getenv("FLASK_SECRET_KEY"))
    sslify = SSLify(app, permanent=True)
    DEBUG = False
else:
    sslify = SSLify(app, permanent=True)
    app.secret_key = '64f5abcf8369e362c36a6220128de068'
    DEBUG = True


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
        return redirect(url_for("login"))


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
    data = {}
    code = 200
    email = request.form['email']
    password = request.form['password']
    salt = get_user_salt(email)
    if salt is not None:
        password_hash = get_hashed_password(password, salt)
        user_id = check_login(email, password_hash, salt)
        if user_id:
            session['email'] = email
            session['password'] = password
            session['user_id'] = user_id

            code, data = json_success("successfully logged in as %s" % escape(session['email']))
        else:
            code, data = json_error(401, "Either the username or password is incorrect")
    else:
        code, data = json_error(401, "Either the username or password is incorrect")

    return write_json(code, data)

@app.route("/login", methods=["GET"])
def login():
    error = None
    return render_template("login.html", login=True, error=error)


@app.route("/logout", methods=["GET"])
def logout():
    if 'email' in session:
        session.pop("email")
    if 'password' in session:
        session.pop("password")
    if 'user_id' in session:
        session.pop("user_id")

    flash("Successfully logged out")
    return redirect(url_for("index"))


@app.route("/entries/new", methods=["GET"])
def new_entry_view():
    if not check_auth():
        return redirect(url_for('index'))
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
    flash("Successfully created account with email %s" % escape(email))
    return redirect(url_for("index"))


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
        return redirect(url_for('index'))

    entries = db_get_entries(session['user_id'])
    dec_entries = decrypt_entries(entries, session['password'])
    return render_template("entries.html", entries=dec_entries)


@app.route("/signup", methods=["POST"])
def signup_api():
    form = SignupForm(request.form)
    if form.validate():
        salt = get_salt(SALT_SIZE)
        password_hash = get_hashed_password(request.form['password'], salt)
        if db_create_account(request.form['email'], password_hash, salt):
            code, data = json_success(
                "Successfully created account with email %s" % request.form['email']
            )
        else:
            code, data = json_error(409, "an account with this email address already exists")
    else:
        code, data = json_form_validation_error(form.errors)
    return write_json(code, data)


@app.route("/signup", methods=["GET"])
def signup():
    error = None
    #flash("Successfully created account with email %s" % request.form['email'])
    return render_template("login.html", login=False, error=error)


@app.route("/advanced/export", methods=["POST"])
def export_entries_api():
    if db_export(DUMP_FILE):
        code, data = json_success("Successfully dumped to file %s" % DUMP_FILE)
    else:
        code, data = json_internal_error("internal error")

    return write_json(code, data)


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

    for field in ['account', 'username', 'password']:
        if field not in request.form:
            code = 400
            data = {
                "status": "error",
                "msg": "field %s is required" % field
            }
            break

    if code == 200:
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
        return redirect(url_for("index"))
    if not entry_id.isdigit():
        return "entry ID must be an integer"

    entry_id = int(str(entry_id))
    entries = db_get_entries(session['user_id'])
    dec_entries = decrypt_entries(entries, session['password'])

    fe = [e for e in dec_entries if e["id"] == entry_id]
    if len(fe) == 0:
        #TODO flash error msg about invalid ID here
        return render_template("index.html")
    else:
        return render_template("new.html", e_id=entry_id, entry=fe[0], error=None)

@app.route("/advanced")
def advanced():
    return render_template("advanced.html")


@app.route("/advanced/password", methods=["UPDATE"])
def update_password_api():
    if check_auth():
        form = UpdatePasswordForm(request.form)
        if form.validate():
            status = db_update_password(
                session['user_id'],
                session['email'],
                request.form['old_password'],
                request.form['new_password']
            )
            if status:
                code, data = json_success("successfully changed password")
            else:
                code, data = json_error(401, "old password is incorrect")
        else:
            code, data = json_form_validation_error(form.errors)
    else:
        code, data = json_noauth()

    return write_json(code, data)


@app.route("/about")
def about():
    return render_template("about.html")


app.wsgi_app = ProxyFix(app.wsgi_app)

if __name__ == "__main__":
    db_init()
    if DEBUG:
        app.debug = True
        app.run(port=PORT, ssl_context=("server.crt", "server.key"))
    else:
        app.debug = False
        app.run(host='0.0.0.0', port=PORT)
