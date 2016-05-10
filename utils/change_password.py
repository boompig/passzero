from __future__ import print_function
from argparse import ArgumentParser
from models import Entry, User
from sqlalchemy import create_engine, MetaData, and_
from sqlalchemy.orm import sessionmaker
from crypto_utils import encrypt_messages, random_bytes, get_kdf_salt, extend_key, decrypt_messages, get_hashed_password
from Crypto.Cipher import AES
import binascii
import logging
import sys
from sqlalchemy.orm.exc import NoResultFound


"""
Encryption scheme works like this:

we have fields ['account', 'username', 'password', 'extra']
    OLDEST VERSION: <padding> + some other bullshit
    OLD VERSION: reuses IV among items

    NEW VERSION: uses IV to create stream cipher, then encrypts all fields in order
        1. account
        2. username
        3. password
        4. extra

    Stream cipher uses IV of AES.block_size, which in pyCrypto is 16 bytes
        - equivalent to 128-bit

    Key used is generated with PBKDF2
        - salted with 32 bytes, so 256-bit key

"""


def decrypt_old_entries(session, user_id, user_key):
    """Return generator over list of tuples
    item is (decrypted_entry, old entry)"""
    results = session.query(Entry).filter_by(
        user_id=user_id, iv=None
    )
    for entry in results:
        dec_entry = decrypt_old_entry(entry, user_key)
        yield (dec_entry, entry)


def find_entries(session, user_id):
    return session.query(Entry).filter_by(
        user_id=user_id, pinned=False)


def decrypt_newer_entries(session, user_id, user_key):
    q = session.query(Entry)
    #.filter_by(
        #user_id = user_id, iv!=None
    #)
    results = q.filter(and_(Entry.user_id == user_id, Entry.iv != None))
    for entry in results:
        dec_entry = decrypt_old_entry(entry, user_key)
        yield (dec_entry, entry)


def encrypt_dec_entry(dec_entry, user_key):
    enc_entry, iv, kdf_salt = encrypt_entry(dec_entry, user_key)
    return {
        "entry": enc_entry,
        "iv": iv,
        "kdf_salt": kdf_salt
    }

def decrypt_old_entry(entry, user_key):
    dec_entry = entry.decrypt(user_key)
    if "account" not in dec_entry:
        dec_entry["account"] = entry.account
    return dec_entry


def base64_encode(bin_data):
    s = binascii.b2a_base64(bin_data)
    if s[-1] == "\n":
        return s[:-1]
    else:
        return s

def encrypt_entry(entry, user_key):
    """First we use a different KDF key for each entry.
    This is equivalent to salting the entry."""
    kdf_salt = get_kdf_salt(num_bytes=32)
    extended_key = extend_key(user_key, kdf_salt)
    fields = ["account", "username", "password", "extra"]
    messages = [entry[field] for field in fields]
    iv = random_bytes(AES.block_size)
    enc_messages = encrypt_messages(extended_key, iv, messages)
    enc_entry = {}
    for field, enc_message in zip(fields, enc_messages):
        enc_entry[field] = base64_encode(enc_message)
    return (enc_entry, base64_encode(iv), base64_encode(kdf_salt))


def insert_new_entry(session, entry_dict, user_id, user_key, is_pinned=False):
    entry = Entry()
    # metadata
    entry.user_id = user_id
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
    entry.pinned = is_pinned
    # old information
    entry.padding = None
    # make sure we can decrypt
    test_decrypt_entry(user_key, entry_dict)
    session.add(entry)


def test_decrypt_entry(user_key, entry):
    # go through the process backwards
    fields = ["account", "username", "password", "extra"]
    messages = [binascii.a2b_base64(entry["entry"][field]) for field in fields]
    kdf_salt = binascii.a2b_base64(entry["kdf_salt"])
    iv = binascii.a2b_base64(entry["iv"])
    extended_key = extend_key(user_key, kdf_salt)
    # TODO this does nothing
    decrypt_messages(extended_key, iv, messages)


def parse_args():
    parser = ArgumentParser()
    parser.add_argument("--email", required=True)
    parser.add_argument("--old-password", required=True)
    parser.add_argument("--new-password", required=True)
    return parser.parse_args()


def find_user_id(session, email, password):
    user = session.query(User).filter_by(email=email).one()
    return user.id


def setup_logging():
    logging.basicConfig(level=logging.INFO)


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
    new_entry = encrypt_dec_entry(dec_entry, master_password)
    insert_new_entry(session, new_entry, user_id, master_password, is_pinned=True)


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
    new_entry = encrypt_dec_entry(dec_entry, new_password)
    insert_new_entry(session, new_entry, user_id, new_password)
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
        logging.error("No pinned entry was found for user ID {}".format(
            user_id
        ))
        session.rollback()
        return False
    reencrypt_entries(session, user_id, old_password, new_password)
    change_password_in_user_table(session, user_id, new_password)
    session.commit()
    return True


def get_session():
    meta = MetaData()
    engine = create_engine("postgres://dbkats:@localhost/dbkats")
    meta.bind = engine
    meta.create_all()
    Session = sessionmaker()
    Session.configure(bind=engine)
    session = Session()
    return session


if __name__ == "__main__":
    args = parse_args()
    setup_logging()
    session = get_session()
    user_id = find_user_id(session, args.email, args.old_password)
    change_password(session, user_id, args.old_password, args.new_password)

