from flask import Flask, render_template, redirect, session, request, url_for, escape, flash, Response
from werkzeug.contrib.fixers import ProxyFix
import json

# some helpers
from crypto_utils import encrypt_password, decrypt_password, pad_key, get_hashed_password, get_salt
from datastore_sqlite3 import db_init, get_user_salt, check_login, get_entries, save_edit_entry, save_entry, export, db_delete_entry

app = Flask(__name__, static_url_path="")
PORT = 5050
SALT_SIZE = 32
DUMP_FILE = "dump.sql"
DEBUG = True


def check_auth():
    """Return True iff user_id and password are in session."""
    return 'user_id' in session and 'password' in session


def json_noauth():
    """Return tuple of (code, json object)"""
    return (401, {
        "status": "error",
        "msg": "must be logged in to perform this action"
    })


def write_json(code, data):
    """Write JSON response. Code is status code."""
    return Response(
        json.dumps(data),
        status=code,
        mimetype="application/json"
    )


@app.route("/entries/<int:entry_id>", methods=["DELETE"])
def delete_entry(entry_id):
    """Print 1 on success and 0 on failure"""
    result = db_delete_entry(session['user_id'], entry_id)
    return ("1" if result else "0")


@app.route("/", methods=["GET"])
def index():
    if check_auth():
        return render_template("index.html",
            logged_in=True,
            email=session['email']
        )
    else:
        return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
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

                return redirect(url_for("index"))
            else:
                error = "Either the username or password is incorrect"
        else:
            error = "Either the username or password is incorrect"
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
    code = 200
    data = {}
    if not check_auth():
        code, data = json_noauth()

    for field in ['account', 'username', 'password']:
        if field not in request.form or request.form[field] == "":
            data = {
                "status": "error",
                "msg": "field %s is required" % field
            }
            code = 400

    if code == 200:
        padding = pad_key(session['password'])
        enc_pass = encrypt_password(session['password'] + padding, request.form['password'])

        status = save_entry(
            session['user_id'],
            request.form['account'],
            request.form['username'],
            enc_pass,
            padding
        )

        if status:
            code = 200
            data = {
                "status": "success",
                "msg": "successfully added account %s" % escape(request.form['account'])
            }
        else:
            code = 500
            data = {
                "status": "error",
                "msg": "internal server error"
            }

    return write_json(code, data)

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

    entries = get_entries(session['user_id'])
    dec_entries = decrypt_entries(entries, session['password'])
    return render_template("entries.html", entries=dec_entries)


@app.route("/signup", methods=["GET", "POST"])
def signup():
    error = None
    if request.method == "POST":
        if 'email' in request.form and 'password' in request.form:
            salt = get_salt(SALT_SIZE)
            password_hash = get_hashed_password(request.form['password'], salt)
            if create_account(request.form['email'], password_hash, salt):
                flash("Successfully created account with email %s" % request.form['email'])
                return redirect(url_for("index"))
            else:
                error = "an account with this email address already exists"
        else:
            error = "must fill in email and password"
    return render_template("login.html", login=False, error=error)

@app.route("/export", methods=["POST"])
def export_entries():
    export(DUMP_FILE)
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
            code = 200
            data = {
                "status": "success",
                "msg": "successfully edited account %s" % escape(request.form["account"])
            }
        else:
            code = 500
            data = {
                "status": "error",
                "msg": "internal server error"
            }

    return write_json(code, data)


@app.route("/edit/<entry_id>", methods=["GET"])
def edit_entry(entry_id):
    if not check_auth():
        return redirect(url_for("index"))
    if not entry_id.isdigit():
        return "entry ID must be an integer"

    entry_id = int(str(entry_id))
    entries = get_entries(session['user_id'])
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


app.wsgi_app = ProxyFix(app.wsgi_app)

if __name__ == "__main__":
    app.secret_key = '64f5abcf8369e362c36a6220128de068'
    db_init()
    if DEBUG:
        app.debug = True
        app.run(port=PORT)
    else:
        app.debug = False
        app.run(host='0.0.0.0', port=PORT)
