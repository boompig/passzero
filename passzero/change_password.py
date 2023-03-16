import logging
from typing import Sequence

from sqlalchemy.orm.exc import NoResultFound

from passzero.backend import create_pinned_entry
from passzero.crypto_utils import get_hashed_password
from passzero.models import Entry, Link, User, EncryptionKeys


def find_entries(session, user_id: int) -> Sequence[Entry]:
    """Find all (non-pinned) entries"""
    return session.query(Entry).filter_by(
        user_id=user_id, pinned=False)


def find_link(session, user_id: int) -> Sequence[Link]:
    return session.query(Link).filter_by(user_id=user_id)


def find_pinned_entry(session, user_id: int) -> Entry:
    assert isinstance(user_id, int)
    return session.query(Entry).filter_by(
        user_id=user_id, pinned=True).one()


def find_user(session, user_id: int) -> User:
    return session.query(User).filter_by(id=user_id).one()


def verify_pinned_entry(session, pinned_entry: Entry, old_password: str) -> None:
    assert isinstance(pinned_entry, Entry)
    assert isinstance(old_password, str)
    dec_entry = pinned_entry.decrypt(old_password)
    assert dec_entry["account"] == "sanity"
    assert dec_entry["username"] == "sanity"
    assert dec_entry["password"] == "sanity"
    assert dec_entry["extra"] == "sanity"


def reencrypt_entry(session, entry: Entry, old_password: str, new_password: str) -> bytes:
    """This method will not bump any entry's version.
    It will keep all entry IDs the same."""
    dec_entry = entry.decrypt(old_password)
    entry_key = entry.encrypt(new_password, dec_entry)
    session.add(entry)
    return entry_key


def reencrypt_link(session, link: Link, old_password: str, new_password: str) -> bytes:
    dec_link = link.decrypt(old_password).to_json()
    link_key = link.encrypt(new_password, dec_link)
    session.add(link)
    return link_key


def reencrypt_entries(session, user_id: int, old_password: str, new_password: str):
    """
    Re-encrypt each entry and update the keys database for those entries
    DO NOT change the password for the keys database here
    DO NOT commit session here
    """
    # guaranteed to exist here
    enc_keys_db = session.query(EncryptionKeys).filter_by(user_id=user_id).one()
    keys_db = enc_keys_db.decrypt(old_password)
    for entry in find_entries(session, user_id):
        entry_key = reencrypt_entry(session, entry, old_password, new_password)
        if str(entry.id) in keys_db["entry_keys"]:
            # don't change the last_modified date
            keys_db["entry_keys"][str(entry.id)]["key"] = entry_key
    # use the old password here
    enc_keys_db.encrypt(old_password, keys_db)
    session.add(enc_keys_db)


def reencrypt_links(session, user_id: int, old_password: str, new_password: str):
    # guaranteed to exist here
    enc_keys_db = session.query(EncryptionKeys).filter_by(user_id=user_id).one()
    keys_db = enc_keys_db.decrypt(old_password)
    for link in find_link(session, user_id):
        link_key = reencrypt_link(session, link, old_password, new_password)
        if str(link.id) in keys_db["link_keys"]:
            # don't change the last_modified date
            keys_db["link_keys"][str(link.id)]["key"] = link_key
    # use the old password here
    enc_keys_db.encrypt(old_password, keys_db)
    session.add(enc_keys_db)


def reencrypt_keys_db(session, user_id: int, old_password: str, new_password: str):
    """Do not commit, just add to session"""
    enc_keys_db = session.query(EncryptionKeys).filter_by(user_id=user_id).one()
    keys_db = enc_keys_db.decrypt(old_password)
    enc_keys_db.encrypt(new_password, keys_db)
    session.add(enc_keys_db)


def change_password_in_user_table(session, user_id: int, new_password: str) -> None:
    assert isinstance(new_password, str)
    user = find_user(session, user_id)
    # the user's salt is represented in the database as unicode but is worked on as bytestring
    # also update the password hashing algo
    user.password = (get_hashed_password(
        password=new_password,
        salt=user.salt.encode('utf-8'),
        hash_algo=User.DEFAULT_PASSWORD_HASH_ALGO
    ).decode("utf-8"))
    user.hash_algo = User.DEFAULT_PASSWORD_HASH_ALGO
    assert isinstance(user.password, str)


def change_password(session, user_id: int, old_password: str, new_password: str) -> bool:
    """Perform the following steps:
    0. Verify using the good old-fashioned way
    1. Verify using pinned entry (auth)
    :param old_password:        User's input of what they *believe* the old password to be (pt)
    :param new_password:        What the user wants to change the password to
    :rtype:                     True iff old_password is correct
    """
    assert isinstance(user_id, int)
    assert isinstance(old_password, str)
    assert isinstance(new_password, str)
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
    reencrypt_links(session, user_id, old_password, new_password)
    reencrypt_keys_db(session, user_id, old_password, new_password)
    change_password_in_user_table(session, user_id, new_password)
    create_pinned_entry(session, user_id, new_password)
    session.commit()
    return True
