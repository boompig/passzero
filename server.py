from flask import Flask, render_template, redirect, session, request, url_for, escape, flash
from werkzeug.contrib.fixers import ProxyFix
import random

# some helpers
from crypto_utils import encrypt_password, decrypt_password, pad_key, get_hashed_password
from datastore_sqlite3 import db_init, get_user_salt, check_login, get_entries, save_edit_entry, save_entry, export, db_delete_entry

app = Flask(__name__, static_url_path="")
PORT = 5050
SALT_SIZE = 32
DUMP_FILE = "dump.sql"
DEBUG = True


@app.route("/entries/<int:entry_id>", methods=["DELETE"])
def delete_entry(entry_id):
    """Print 1 on success and 0 on failure"""
    result = db_delete_entry(session['user_id'], entry_id)
    return ("1" if result else "0")


@app.route("/", methods=["GET"])
def index():
    if 'email' in session:
        return render_template("index.html",
            logged_in=('email' in session),
            email=(session['email'] if 'email' in session else None)
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
    return redirect(url_for("index"))


@app.route("/new", methods=["GET", "POST"])
def new_entry():
    error = None
    if request.method == "POST":
        if 'user_id' not in session or 'password' not in session:
            error = "must be logged in to perform this action"

        for field in ['account', 'username', 'password']:
            if field not in request.form or request.form[field] == "":
                error = "field %s is required" % field
                break

        if error is None:
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
                flash("successfully added account %s" % request.form['account'])
            else:
                error = "internal server error"
    else:
        if 'email' not in session or 'password' not in session:
            return redirect(url_for('index'))

    return render_template("new.html", error=error)

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
    # login-only method
    if 'user_id' not in session or 'password' not in session:
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
            if create_account(request.form['email'], request.form['password']):
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


@app.route("/doedit/<entry_id>", methods=["POST"])
def do_edit_entry(entry_id):
    if 'user_id' not in session or 'password' not in session:
        #TODO something smarter here
        return redirect(url_for("index"))

    for field in ['account', 'username', 'password']:
        if field not in request.form:
            #TODO something smarter here
            return redirect(url_form("index"))

    padding = pad_key(session['password'])
    enc_pass = encrypt_password(session['password'] + padding, request.form['password'])

    save_edit_entry(
        session['user_id'],
        entry_id,
        request.form['account'],
        request.form['username'],
        enc_pass,
        padding
    )
    flash("Successfully changed entry for account %s" % request.form['account'])
    return redirect(url_for("view_entries"))

@app.route("/edit/<entry_id>", methods=["GET"])
def edit_entry(entry_id):
    if 'user_id' not in session or 'password' not in session:
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
    app.secret_key = 'A4Zr98j/3yxmR~XHH!jmN]LWX/,!zT'
    db_init()
    if DEBUG:
        app.debug = True
        app.run(port=PORT)
    else:
        app.debug = False
        app.run(host='0.0.0.0', port=PORT)
