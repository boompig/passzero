from flask import Flask, render_template, redirect, session, request, url_for, escape, flash
import sqlite3

app = Flask(__name__, static_url_path="")
PORT = 5050
DB_FILE = "passzero.db"
DB_INIT_SCRIPT = "db_init.sql"

def db_init():
    with open(DB_INIT_SCRIPT) as f:
        conn = sqlite3.connect(DB_FILE)
        conn.executescript(f.read())
        conn.commit()
        conn.close()
    return True

def check_login(email, password):
    # fetch user_id from database
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("SELECT id FROM users WHERE email=? AND password=?", 
        [
            email,
            password
        ]
    )

    seq = cur.fetchone()
    return (seq[0] if seq else None)

@app.route("/", methods=["GET"])
def index():
    return render_template("index.html",
        logged_in=('email' in session),
        email=(session['email'] if 'email' in session else None)
    )

@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        email = request.form['email']
        password = request.form['password']
        user_id = check_login(email, password)
        if user_id:
            session['email'] = email
            session['password'] = password
            session['user_id'] = user_id

            return redirect(url_for("index"))
        else:
            error = "Either the username or password is incorrect"
    return render_template("login.html", error=error)

@app.route("/logout", methods=["GET"])
def logout():
    if 'email' in session:
        session.pop("email")
    if 'password' in session:
        session.pop("password")
    return redirect(url_for("index"))

def save_entry(user_id, account_name, account_username, account_password):
    sql = "INSERT INTO entries (user, account, username, password) VALUES (?, ?, ?, ?)"
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute(sql, [user_id, account_name, account_username, account_password])
    conn.commit()
    conn.close()
    return True

@app.route("/new", methods=["GET", "POST"])
def new_entry():
    error = None
    if request.method == "POST":
        if 'user_id' not in session:
            error = "must be logged in to perform this action"

        for field in ['account', 'username', 'password']:
            if field not in request.form or request.form[field] == "":
                error = "field %s is required" % field
                break

        if error is None:
            status = save_entry(
                session['user_id'],
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

@app.route("/view", methods=["GET"])
def view_entries():
    # login-only method
    if 'user_id' not in session:
        return redirect(url_for('index'))

    conn = sqlite3.connect(DB_FILE)
    cur = con.cursor()
    cur.execute("select account, username, password from entries where id=?", session['user_id'])


if __name__ == "__main__":
    app.debug = True
    app.secret_key = 'A4Zr98j/3yxmR~XHH!jmN]LWX/,!zT'
    db_init()
    app.run(port=PORT)
