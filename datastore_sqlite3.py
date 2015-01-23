import sqlite3

DB_FILE = "passzero.db"
DB_INIT_SCRIPT = "db_init.sql"


def db_init():
    with open(DB_INIT_SCRIPT) as f:
        conn = sqlite3.connect(DB_FILE)
        conn.executescript(f.read())
        conn.commit()
        conn.close()
    return True

def get_entries(user_id):
    """Return a list of entries as a list of dicts mapping column names to values"""

    sql = "SELECT id, account, username, password, padding from entries where user=? order by lower(account)"

    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute(sql, [user_id])
    entries = cur.fetchall()
    conn.close()
    return entries


def check_login(email, password_hash, salt):
    """Return user ID on success, None on failure"""

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


def save_entry(user_id, account_name, account_username, enc_pass, padding):
    """Save the given entry into the database. Return True on success, False on failure."""

    sql = "INSERT INTO entries (user, account, username, password, padding) VALUES (?, ?, ?, ?, ?)"
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute(sql, [user_id, account_name, account_username, enc_pass, padding])
    conn.commit()
    conn.close()
    return True


#TODO do not import 
def create_account(email, password, salt):
    """Create a new account. Return True on success, False on failure."""
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


def get_user_salt(email):
    """Return the salt if the email is present, None otherwise"""

    sql = "SELECT salt FROM users where email=?"
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute(sql, [email])
    row = cursor.fetchone()
    conn.close()
    return (row[0] if row else None)


def save_edit_entry(user_id, account_id, account_name, account_username, enc_password, padding):
    """Save the edited entry in the DB. Return True on success, False on failure"""

    sql = "UPDATE entries SET user=?, account=?, username=?, password=?, padding=? WHERE id=?";
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute(sql, [user_id, account_name, account_username, enc_password, padding, account_id])
    conn.commit()
    conn.close()
    return True


def export(fname):
    """Export database dump to file."""
    conn = sqlite3.connect(DB_FILE)
    with open(fname, "w") as fp:
        for line in conn.iterdump():
            fp.write("%s\n" % line)
    conn.close()
