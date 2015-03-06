import psycopg2
import psycopg2.extras
import os
import StringIO

# helpers
from crypto_utils import get_hashed_password, pad_key, encrypt_password


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


def db_init():
    conn = db_connect()
    with open(DB_INIT_SCRIPT) as fp:
        cursor = conn.cursor()
        sql = fp.read()
        cursor.execute(sql)
    conn.commit()
    conn.close()

def get_user_salt(email):
    conn = db_connect()
    cur = conn.cursor()
    cur.execute("SELECT salt FROM users WHERE email=%s", [email])
    salt = cur.fetchone()[0]
    conn.close()
    return salt


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
