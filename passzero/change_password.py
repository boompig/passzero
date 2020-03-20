from __future__ import print_function

import logging
from typing import Sequence

import six
from sqlalchemy.orm.exc import NoResultFound

from passzero.backend import encrypt_entry, insert_new_entry
from passzero.crypto_utils import get_hashed_password
from passzero.models import Entry, User


def find_entries(session, user_id: int) -> Sequence[Entry]:
    return session.query(Entry).filter_by(
        user_id=user_id, pinned=False)


def find_pinned_entry(session, user_id: int) -> Entry:
    assert isinstance(user_id, int)
    return session.query(Entry).filter_by(
        user_id=user_id, pinned=True).one()


def create_pinned_entry(session, user_id: int, master_password: str) -> None:
    assert isinstance(user_id, int)
    assert isinstance(master_password, six.text_type)
    dec_entry = {
        "account": "sanity",
        "username": "sanity",
        "password": "sanity",
        "extra": "sanity",
        "has_2fa": False
    }
    new_entry = encrypt_entry(master_password, dec_entry)
    new_entry.pinned = True
    insert_new_entry(session, new_entry, user_id)


def find_user(session, user_id: int) -> User:
    return session.query(User).filter_by(id=user_id).one()


def verify_pinned_entry(session, pinned_entry: Entry, old_password: str) -> None:
    assert isinstance(pinned_entry, Entry)
    assert isinstance(old_password, six.text_type)
    dec_entry = pinned_entry.decrypt(old_password)
    assert dec_entry["account"] == "sanity"
    assert dec_entry["username"] == "sanity"
    assert dec_entry["password"] == "sanity"
    assert dec_entry["extra"] == "sanity"


def reencrypt_entry(session, old_entry: Entry, user_id: int, old_password: str, new_password: str) -> None:
    dec_entry = old_entry.decrypt(old_password)
    new_entry = encrypt_entry(new_password, dec_entry)
    # reuse ID from deleted entry
    new_entry.id = old_entry.id
    # order matters here. delete before insert.
    session.delete(old_entry)
    insert_new_entry(session, new_entry, user_id)


def reencrypt_entries(session, user_id: int, old_password: str, new_password: str) -> int:
    n = 0
    for old_entry in find_entries(session, user_id):
        reencrypt_entry(session, old_entry, user_id, old_password, new_password)
        n += 1
    return n


def change_password_in_user_table(session, user_id: int, new_password: str) -> None:
    assert isinstance(new_password, six.text_type)
    user = find_user(session, user_id)
    # the user's salt is represented in the database as unicode but is worked on as bytestring
    # also update the password hashing algo
    user.password = (get_hashed_password(
        password=new_password,
        salt=user.salt.encode('utf-8'),
        hash_algo=User.DEFAULT_PASSWORD_HASH_ALGO
    ).decode("utf-8"))
    user.hash_algo = User.DEFAULT_PASSWORD_HASH_ALGO
    assert isinstance(user.password, six.text_type)


def change_password(session, user_id: int, old_password: str, new_password: str) -> bool:
    """Perform the following steps:
    0. Verify using the good old-fashioned way
    1. Verify using pinned entry (auth)
    :param old_password:        User's input of what they *believe* the old password to be (pt)
    :param new_password:        What the user wants to change the password to
    :rtype:                     True iff old_password is correct
    """
    assert isinstance(user_id, int)
    assert isinstance(old_password, six.text_type)
    assert isinstance(new_password, six.text_type)
    # do proper authentication
    user = find_user(session, user_id)
    if not user.authenticate(old_password):
        logging.debug("[change_password] Hashed password is not the same as user password")
        session.rollback()
        return False
    # do sanity decryption
    try:
        pinned_entry = find_pinned_entry(session, user_id)
        verify_pinned_entry(session, pinned_entry, old_password)
        logging.info("[change_password] Verified pinned entry")
        session.delete(pinned_entry)
    except NoResultFound:
        logging.warning("[change_password] No pinned entry was found for user ID {}".format(
            user_id
        ))
    reencrypt_entries(session, user_id, old_password, new_password)
    change_password_in_user_table(session, user_id, new_password)
    create_pinned_entry(session, user_id, new_password)
    session.commit()
    return True
