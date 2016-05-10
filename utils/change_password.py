from __future__ import print_function
from Crypto.Cipher import AES
from crypto_utils import encrypt_messages, random_bytes, get_kdf_salt, extend_key, get_hashed_password
from models import Entry, User
from sqlalchemy.orm.exc import NoResultFound
import binascii
import logging


def find_entries(session, user_id):
    return session.query(Entry).filter_by(
        user_id=user_id, pinned=False)


def base64_encode(bin_data):
    s = binascii.b2a_base64(bin_data)
    if s[-1] == "\n":
        return s[:-1]
    else:
        return s


def encrypt_entry(entry, user_key):
    """First we use a different KDF key for each entry.
    This is equivalent to salting the entry.
    Return Entry object"""
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


def insert_new_entry(session, entry, user_id):
    entry.user_id = user_id
    session.add(entry)


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
    new_entry = encrypt_entry(dec_entry, master_password)
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
    new_entry = encrypt_entry(dec_entry, new_password)
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


