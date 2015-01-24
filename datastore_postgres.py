import psycopg2
import psycopg2.extras

DB_INIT_SCRIPT = "db_init_postgres.sql"
DB_NAME = "dbkats"
DB_USER = "dbkats"

def db_connect():
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


def save_entry(user_id, account_name, account_username, enc_pass, padding):
    """Save the given entry into the database. Return True on success, False on failure."""

    sql = "INSERT INTO entries (user_id, account, username, password, padding) VALUES (%s, %s, %s, %s, %s)"
    conn = db_connect()
    cur = conn.cursor()
    cur.execute(sql, [user_id, account_name, account_username, enc_pass, padding])
    conn.commit()
    conn.close()
    return True


def db_create_account(email, password_hash, salt):
    """Create a new account. Return True on success, False on failure."""

    sql = "INSERT INTO users (email, password, salt) VALUES (%s, %s, %s)";
    try:
        conn = db_connect()
        cur = conn.cursor()
        cur.execute(sql, [email, password_hash, salt])
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


def save_edit_entry(user_id, account_id, account_name, account_username, enc_password, padding):
    """Save the edited entry in the DB. Return True on success, False on failure"""

    sql = "UPDATE entries SET user_id=%s, account=%s, username=%s, password=%s, padding=%s WHERE id=%s";
    conn = db_connect()
    cur = conn.cursor()
    cur.execute(sql, [user_id, account_name, account_username, enc_password, padding, account_id])
    conn.commit()
    conn.close()
    return True


def db_export(fname):
    """Export database dump to file."""
    conn = db_connect()
    with open(fname, "w") as fp:
        for line in conn.iterdump():
            fp.write("%s\n" % line)
    conn.close()
    return True


def db_delete_entry(user_id, entry_id):
    """Return True on success, False on failure"""

    sql = "DELETE FROM entries WHERE id=%s AND user_id=%s"
    conn = db_connect()
    cur = conn.cursor()
    cur.execute(sql, [entry_id, user_id])
    conn.commit()
    result = conn.total_changes
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

if __name__ == "__main__":
    db_init()
    rows = db_get_entries(1)
    print rows
