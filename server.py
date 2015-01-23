from flask import Flask, render_template, redirect, session, request, url_for, escape, flash
from werkzeug.contrib.fixers import ProxyFix
import sqlite3
import random
import hashlib

# some helpers
from utils import encrypt_password, decrypt_password, pad_key

app = Flask(__name__, static_url_path="")
PORT = 5050
DB_FILE = "passzero.db"
DB_INIT_SCRIPT = "db_init.sql"
SALT_SIZE = 32
DUMP_FILE = "dump.sql"
DEBUG = True

def db_init():
    with open(DB_INIT_SCRIPT) as f:
        conn = sqlite3.connect(DB_FILE)
        conn.executescript(f.read())
        conn.commit()
        conn.close()
    return True

def get_hashed_password(password, salt):
    return hashlib.sha512(password + salt).hexdigest()

def check_login(email, password, salt):
    """Return user ID on success, None on failure"""
    password_hash = get_hashed_password(password, salt)
    # fetch user_id from database
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("SELECT id FROM users WHERE email=? AND password=?", 
        [
            email,
            password_hash
        ]
    )

    seq = cur.fetchone()
    conn.close()
    return (seq[0] if seq else None)

@app.route("/", methods=["GET"])
def index():
    if 'email' in session:
        return render_template("index.html",
            logged_in=('email' in session),
            email=(session['email'] if 'email' in session else None)
        )
    else:
        return redirect(url_for("login"))

def get_user_salt(email):
    """Return the salt if the email is present, None otherwise"""
    sql = "SELECT salt FROM users where email=?"
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute(sql, [email])
    row = cursor.fetchone()
    conn.close()
    return (row[0] if row else None)


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        email = request.form['email']
        password = request.form['password']
        salt = get_user_salt(email)
        if salt is not None:
            user_id = check_login(email, password, salt)
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

def save_entry(user_id, key, account_name, account_username, account_password):
    padding = pad_key(key)
    enc_pass = encrypt_password(key + padding, account_password)

    sql = "INSERT INTO entries (user, account, username, password, padding) VALUES (?, ?, ?, ?, ?)"
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute(sql, [user_id, account_name, account_username, enc_pass, padding])
    conn.commit()
    conn.close()
    return True

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
            status = save_entry(
                session['user_id'],
                session['password'],
                request.form['account'],
                request.form['username'],
                request.form['password']
            )

            if status:
                flash("successfully added account %s" % request.form['account'])
            else:
                error = "internal server error"
    else:
        if 'email' not in session or 'password' not in session:
            return redirect(url_for('index'))

    return render_template("new.html", error=error)

def get_entries(user_id):
    sql = "select id, account, username, password, padding from entries where user=? order by lower(account)"

    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute(sql, [user_id])
    entries = cur.fetchall()
    conn.close()
    return entries

def decrypt_entries(entries, key):
    obj = []
    for row in entries:
        hex_ciphertext = row["password"]
        padding = row[4]
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

def get_salt(size):
    """Create and return random salt of given size"""
    alphabet = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    chars = []
    for i in range(size):
        chars.append(random.choice(alphabet))
    return "".join(chars)

def create_account(email, password):
    salt = get_salt(SALT_SIZE)
    password_hash = get_hashed_password(password, salt)

    sql = "INSERT INTO users (email, password, salt) VALUES (?, ?, ?)";
    try:
        conn = sqlite3.connect(DB_FILE)
        cur = conn.cursor()
        cur.execute(sql, [email, password_hash, salt])
        conn.commit()
        conn.close()
        return True
    except sqlite3.IntegrityError:
        return False

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
    conn = sqlite3.connect(DB_FILE)
    with open(DUMP_FILE, "w") as fp:
        for line in conn.iterdump():
            fp.write("%s\n" % line)
    conn.close()

    flash("database successfully dumped to file %s" % DUMP_FILE)
    return redirect("/advanced")

def save_edit_entry(user_id, key, account_id, account_name, account_username, account_password):
    padding = pad_key(key)
    enc_pass = encrypt_password(key + padding, account_password)

    sql = "UPDATE entries SET user=?, account=?, username=?, password=?, padding=? WHERE id=?";
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute(sql, [user_id, account_name, account_username, enc_pass, padding, account_id])
    conn.commit()
    conn.close()
    return True

@app.route("/doedit/<entry_id>", methods=["POST"])
def do_edit_entry(entry_id):
    if 'user_id' not in session or 'password' not in session:
        #TODO something smarter here
        return redirect(url_for("index"))

    for field in ['account', 'username', 'password']:
        if field not in request.form:
            #TODO something smarter here
            return redirect(url_form("index"))

    save_edit_entry(
        session['user_id'],
        session['password'],
        entry_id,
        request.form['account'],
        request.form['username'],
        request.form['password']
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
