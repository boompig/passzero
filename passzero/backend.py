from Crypto.Cipher import AES
from passzero.crypto_utils import get_salt, encrypt_messages, random_bytes, get_kdf_salt, extend_key, get_hashed_password
from passzero.config import SALT_SIZE
from passzero.models import AuthToken, Entry, User
from sqlalchemy import func
from sqlalchemy.sql.expression import asc
import binascii


def activate_account(db_session, user):
    """Set the user to active and commit changes"""
    user.active = True
    db_session.add(user)
    db_session.commit()


def base64_encode(bin_data):
    s = binascii.b2a_base64(bin_data)
    if s[-1] == "\n":
        return s[:-1]


def _decrypt_row(row, key):
    obj = row.decrypt(key)
    obj["id"] = row.id
    return obj


def decrypt_entries(entries, key):
    """Return a list of objects representing the decrypted entries"""
    return [_decrypt_row(row, key) for row in entries]


def get_entries(db_session, user_id):
    return db_session.query(Entry)\
        .filter_by(user_id=user_id, pinned=False)\
        .order_by(asc(func.lower(Entry.account)))\
        .all()


def create_entry_from_dict(entry_dict):
    entry = Entry()
    # entry contents
    entry.account = entry_dict["entry"]["account"]
    entry.username = entry_dict["entry"]["username"]
    entry.password = entry_dict["entry"]["password"]
    entry.extra = entry_dict["entry"]["extra"]
    # encryption info
    entry.key_salt = entry_dict["kdf_salt"]
    entry.iv = entry_dict["iv"]
    # more metadata - which encryption scheme to use to decrypt
    entry.version = 3
    entry.pinned = False
    # old information
    entry.padding = None
    return entry


def get_account_with_email(db_session, email):
     return db_session.query(User).filter_by(email=email).one()


def delete_all_entries(db_session, user):
    entries = db_session.query(Entry).filter_by(user_id=user.id).all()
    for entry in entries:
        db_session.delete(entry)
    db_session.commit()


def delete_all_auth_tokens(db_session, user):
    auth_tokens = db_session.query(AuthToken).filter_by(user_id=user.id).all()
    for token in auth_tokens:
        db_session.delete(token)
    db_session.commit()


def delete_account(db_session, user):
    """Delete the given user from the database."""
    db_session.delete(user)
    db_session.commit()


def create_inactive_user(db_session, email, password):
    """Create an account which has not been activated.
    Return the user object (model)"""
    salt = get_salt(SALT_SIZE)
    password_hash = get_hashed_password(password, salt)
    user = User()
    user.email = email
    user.password = password_hash
    user.salt = salt
    user.active = False
    # necessary to get user ID
    db_session.add(user)
    db_session.commit()
    return user


def encrypt_entry(entry, user_key):
    """We use a different KDF key for each entry.
    This is equivalent to salting the entry.
    :param entry: A dictionary representing the decrypted entry
    :param user_key: A string representing the user's key
    :return: Entry object"""
    kdf_salt = get_kdf_salt(num_bytes=32)
    extended_key = extend_key(user_key, kdf_salt)
    fields = ["account", "username", "password", "extra"]
    messages = [entry[field] for field in fields]
    iv = random_bytes(AES.block_size)
    enc_messages = encrypt_messages(extended_key, iv, messages)
    enc_entry = {}
    for field, enc_message in zip(fields, enc_messages):
        enc_entry[field] = base64_encode(enc_message)
    entry_dict = {
        "entry": enc_entry,
        "kdf_salt": base64_encode(kdf_salt),
        "iv": base64_encode(iv)
    }
    return create_entry_from_dict(entry_dict)

