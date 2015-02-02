import psycopg2
import psycopg2.extras
import os
import StringIO

# helpers
from crypto_utils import get_hashed_password, pad_key, encrypt_password, random_hex


DB_INIT_SCRIPT = "db_init_postgres.sql"
DB_NAME = "dbkats"
DB_USER = "dbkats"


def db_connect():
    if 'DATABASE_URL' in os.environ:
        return psycopg2.connect(os.environ['DATABASE_URL'])
    else:
        return psycopg2.connect(
            dbname=DB_NAME,
            user=DB_USER,
            host="localhost",
            password=""
        )


def db_get_entries(user_id):
    """Return a list of entries as a list of dicts mapping column names to values"""

    sql = "SELECT id, account, username, password, padding from entries where user_id=%s ORDER BY LOWER(account)"

    conn = db_connect()
    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    cur.execute(sql, [user_id])
    entries = cur.fetchall()
    conn.close()
    return entries


def check_login(email, password_hash, salt):
    """Return user ID on success, None on failure"""

    # fetch user_id from database
    conn = db_connect()
    cur = conn.cursor()
    cur.execute("SELECT id FROM users WHERE email=%s AND password=%s", 
        [
            email,
            password_hash
        ]
    )

    seq = cur.fetchone()
    conn.close()
    return (seq[0] if seq else None)


def db_save_entry(user_id, account_name, account_username, enc_pass, padding):
    """Save the given entry into the database. Return True on success, False on failure."""

    sql = "INSERT INTO entries (user_id, account, username, password, padding) VALUES (%s, %s, %s, %s, %s)"
    try:
        conn = db_connect()
        cur = conn.cursor()
        cur.execute(sql, [user_id, account_name, account_username, enc_pass, padding])
        conn.commit()
        conn.close()
        return True
    except psycopg2.IntegrityError as e:
        print e
        return False


def db_create_account(email, password_hash, salt, token):
    """Create a new account. Return True on success, False on failure."""

    sql = "INSERT INTO users (email, password, salt) VALUES (%s, %s, %s) RETURNING id"
    token_sql = "INSERT INTO auth_tokens (user_id, token) VALUES (%s, %s)"
    try:
        conn = db_connect()
        cur = conn.cursor()
        cur.execute(sql, [email, password_hash, salt])
        user_id = cur.fetchone()[0]
        cur.execute(token_sql, [user_id, token])
        conn.commit()
        conn.close()
        return True
    except psycopg2.IntegrityError as e:
        print e
        return False


def get_user_salt(email):
    """Return the salt if the email is present, None otherwise"""

    sql = "SELECT salt FROM users WHERE email=%s"
    conn = db_connect()
    cursor = conn.cursor()
    cursor.execute(sql, [email])
    row = cursor.fetchone()
    conn.close()
    return (row[0] if row else None)


def save_edit_entry(user_id, entry_id, account_name, account_username, enc_password, padding):
    """Save the edited entry in the DB. Return True on success, False on failure"""

    sql = "UPDATE entries SET user_id=%s, account=%s, username=%s, password=%s, padding=%s WHERE id=%s";
    conn = db_connect()
    cur = conn.cursor()
    cur.execute(sql, [user_id, account_name, account_username, enc_password, padding, entry_id])
    conn.commit()
    conn.close()
    return True


def db_export(user_id):
    """Export database dump to file."""
    #TODO this is stupidly unsafe
    sql = "COPY (select * FROM entries WHERE user_id=%s) TO STDOUT WITH (FORMAT CSV, HEADER TRUE)" % user_id

    conn = db_connect()
    cur = conn.cursor()
    contents = StringIO.StringIO()
    cur.copy_expert(sql, contents)
    conn.close()
    val = contents.getvalue()
    contents.close()
    return val


def db_delete_entry(user_id, entry_id):
    """Return True on success, False on failure"""

    sql = "DELETE FROM entries WHERE id=%s AND user_id=%s"
    conn = db_connect()
    cur = conn.cursor()
    cur.execute(sql, [entry_id, user_id])
    result = cur.rowcount
    conn.commit()
    conn.close()
    return result > 0

def db_init():
    conn = db_connect()
    with open(DB_INIT_SCRIPT) as fp:
        cursor = conn.cursor()
        sql = fp.read()
        cursor.execute(sql)
    conn.commit()
    conn.close()


def db_update_password(user_id, user_email, old_password, new_password, entries):
    """Return True on success, False on failure."""
    salt = get_user_salt(user_email)
    password_hash = get_hashed_password(old_password, salt)
    checked_user_id = check_login(user_email, password_hash, salt)
    if checked_user_id == user_id:
        password_hash = get_hashed_password(new_password, salt)
        sql = "UPDATE users SET password=%s WHERE id=%s"
        conn = db_connect()
        cur = conn.cursor()

        for entry in entries:
            padding = pad_key(new_password)
            enc_password = encrypt_password(new_password + padding, entry["password"])
            save_edit_entry(user_id, entry["id"], entry["account"], entry["username"], enc_password, padding)
        # change password last
        cur.execute(sql, [password_hash, user_id])
        conn.commit()

        conn.close()
        return True
    else:
        return False

def db_confirm_signup(token):
    """Return True on success, False on failure"""
    conn = db_connect()
    cur = conn.cursor()
    sql = "SELECT user_id FROM auth_tokens WHERE token=%s"
    cur.execute(sql, [token])
    row = cur.fetchone()

    if row is None:
        # no such token
        return False

    user_id = row[0]

    update_sql = "UPDATE users SET active=TRUE where id=%s"
    cur.execute(update_sql, [user_id])
    conn.commit()
    conn.close()
    return True
