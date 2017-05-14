from __future__ import print_function
from passzero.backend import encrypt_entry, insert_new_entry
from passzero.crypto_utils import get_hashed_password
from passzero.models import Entry, User
from sqlalchemy.orm.exc import NoResultFound
import logging


def find_entries(session, user_id):
    return session.query(Entry).filter_by(
        user_id=user_id, pinned=False)


def find_pinned_entry(session, user_id):
    return session.query(Entry).filter_by(
        user_id=user_id, pinned=True).one()


def create_pinned_entry(session, user_id, master_password):
    dec_entry = {
        "account": "sanity",
        "username": "sanity",
        "password": "sanity",
        "extra": "sanity"
    }
    new_entry = encrypt_entry(master_password, dec_entry)
    new_entry.pinned = True
    insert_new_entry(session, new_entry, user_id)


def find_user(session, user_id):
    return session.query(User).filter_by(id=user_id).one()


def verify_pinned_entry(session, pinned_entry, old_password):
    dec_entry = pinned_entry.decrypt(old_password)
    assert dec_entry["account"] == "sanity"
    assert dec_entry["username"] == "sanity"
    assert dec_entry["password"] == "sanity"
    assert dec_entry["extra"] == "sanity"


def reencrypt_entry(session, old_entry, user_id, old_password, new_password):
    dec_entry = old_entry.decrypt(old_password)
    new_entry = encrypt_entry(new_password, dec_entry)
    insert_new_entry(session, new_entry, user_id)
    session.delete(old_entry)


def reencrypt_entries(session, user_id, old_password, new_password):
    n = 0
    for old_entry in find_entries(session, user_id):
        reencrypt_entry(session, old_entry, user_id, old_password, new_password)
        n += 1
    return n


def change_password_in_user_table(session, user_id, new_password):
    user = find_user(session, user_id)
    user.password = get_hashed_password(new_password, user.salt)


def change_password(session, user_id, old_password, new_password):
    """Perform the following steps:
    0. Verify using the good old-fashioned way
    1. Verify using pinned entry (auth)
    """
    # do proper authentication
    user = find_user(session, user_id)
    hashed_password = get_hashed_password(old_password, user.salt)
    if hashed_password != user.password:
        session.rollback()
        return False
    # do sanity decryption
    try:
        pinned_entry = find_pinned_entry(session, user_id)
        verify_pinned_entry(session, pinned_entry, old_password)
        logging.info("Verified pinned entry")
        session.delete(pinned_entry)
    except NoResultFound:
        logging.warning("No pinned entry was found for user ID {}".format(
            user_id
        ))
    reencrypt_entries(session, user_id, old_password, new_password)
    change_password_in_user_table(session, user_id, new_password)
    create_pinned_entry(session, user_id, new_password)
    session.commit()
    return True


