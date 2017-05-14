from sqlalchemy import func
from sqlalchemy.sql.expression import asc

from passzero.config import SALT_SIZE
from passzero.crypto_utils import get_hashed_password, get_salt
from passzero.models import AuthToken, Entry, User


def activate_account(db_session, user):
    """Set the user to active and commit changes"""
    user.active = True
    db_session.add(user)
    db_session.commit()


def _decrypt_row(row, key):
    obj = row.decrypt(key)
    obj["id"] = row.id
    return obj


def decrypt_entries_pool(entry_key_pair):
    row, key = entry_key_pair
    result = _decrypt_row(row, key)
    return result


def _decrypt_entries_multiprocess(entries, key):
    from multiprocessing import Pool
    pool = Pool(5)
    entry_key_pairs = [(entry, key) for entry in entries]
    results = pool.map(decrypt_entries_pool, entry_key_pairs)
    pool.close()
    pool.join()
    return results


def _decrypt_entries_single_thread(entries, key):
    return [_decrypt_row(row, key) for row in entries]


def decrypt_entries(entries, key):
    """Return a list of objects representing the decrypted entries"""
    return _decrypt_entries_multiprocess(entries, key)


def get_entries(db_session, user_id):
    return db_session.query(Entry)\
        .filter_by(user_id=user_id, pinned=False)\
        .order_by(asc(func.lower(Entry.account)))\
        .all()


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
    """Delete the given user from the database.
    Also delete all entries associated with that user"""
    db_session.query(Entry).filter_by(user_id=user.id).delete()
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


def insert_entry_for_user(db_session, dec_entry, user_id, user_key, version=4):
    entry = encrypt_entry(user_key, dec_entry, version=version)
    insert_new_entry(db_session, entry, user_id)
    db_session.commit()
    return entry


def insert_new_entry(session, entry, user_id):
    entry.user_id = user_id
    session.add(entry)


def encrypt_entry(user_key, dec_entry, version=4):
    """
    A different KDF key is used for each entry.
    This is equivalent to salting the entry.
    :param dec_entry:   A dictionary representing the decrypted entry
    :param user_key:    A string representing the user's key
    :return:            Entry object
    """
    entry = Entry()
    if version == 4:
        entry.encrypt_v4(user_key, dec_entry)
    else:
        entry.encrypt_v3(user_key, dec_entry)
    return entry

