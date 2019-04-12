import six
from sqlalchemy import func
from sqlalchemy.orm.session import Session
from sqlalchemy.sql.expression import asc
from typing import Any, Dict, List, Tuple

from passzero import audit
from passzero.config import SALT_SIZE, DEFAULT_ENTRY_VERSION
from passzero.crypto_utils import get_hashed_password, get_salt, PasswordHashAlgo
from passzero.models import (AuthToken, DecryptedDocument, EncryptedDocument,
                             Entry, Service, User, Entry_v4, Entry_v3, Entry_v5, Link)

from .utils import base64_encode


def activate_account(db_session: Session, user: User):
    """Set the user to active and commit changes"""
    user.active = True
    db_session.add(user)
    db_session.commit()


def password_strength_scores(email: str, dec_entries: list) -> List[Dict[str, Any]]:
    dec_entries_json = []
    for entry in dec_entries:
        d = {}
        d["account"] = entry["account"]
        results = audit.password_strength(entry["password"], user_inputs=[
            entry["account"], entry["username"], email
        ])
        d["score"] = results["score"]
        d["feedback"] = " ".join(results["feedback"]["suggestions"])
        if entry["password"] == "" or entry["password"] == "-":
            continue
        dec_entries_json.append(d)
    return dec_entries_json


def decrypt_entries_pool(entry_key_pair: Tuple[Entry, str]) -> dict:
    entry, key = entry_key_pair
    result = entry.decrypt(key)
    return result


def _decrypt_entries_multiprocess(entries: List[Entry], key: str) -> List[dict]:
    from multiprocessing import Pool
    pool = Pool(5)
    entry_key_pairs = [(entry, key) for entry in entries]
    results = pool.map(decrypt_entries_pool, entry_key_pairs)
    pool.close()
    pool.join()
    return results


def _decrypt_entries_single_thread(entries: List[Entry], key: str) -> List[dict]:
    return [entry.decrypt(key) for entry in entries]


def decrypt_entries(entries: List[Entry], key: str) -> List[dict]:
    """Return a list of objects representing the decrypted entries
    :param entries:         List[Entry]
    :param key:             Unicode string
    :rtype:                 List[dict]"""
    assert isinstance(key, six.text_type)
    # return _decrypt_entries_multiprocess(entries, key)
    return _decrypt_entries_single_thread(entries, key)


def get_entries(db_session: Session, user_id: int) -> List[Entry]:
    """Return a list of entries without decrypting them"""
    assert isinstance(user_id, int)
    return db_session.query(Entry)\
        .filter_by(user_id=user_id, pinned=False)\
        .order_by(asc(func.lower(Entry.account)))\
        .all()


def get_links(db_session: Session, user_id: int) -> List[Link]:
    """Return a list of links without decrypting them"""
    assert isinstance(user_id, int)
    return db_session.query(Link)\
        .filter_by(user_id=user_id)\
        .all()


def get_account_with_email(db_session: Session, email: str) -> User:
    assert isinstance(email, six.text_type)
    return db_session.query(User).filter_by(email=email).one()


def delete_all_entries(db_session: Session, user: User) -> None:
    entries = db_session.query(Entry).filter_by(user_id=user.id).all()
    for entry in entries:
        db_session.delete(entry)
    db_session.commit()


def delete_account(db_session: Session, user: User) -> None:
    """Delete the given user from the database.
    Also delete all entries associated with that user
    Also delete all documents associated with that user
    Delete all data for that user across all tables"""
    entries = db_session.query(Entry).filter_by(user_id=user.id).all()
    for entry in entries:
        db_session.delete(entry)
    auth_tokens = db_session.query(AuthToken).filter_by(user_id=user.id).all()
    for token in auth_tokens:
        db_session.delete(token)
    docs = db_session.query(EncryptedDocument).filter_by(user_id=user.id).all()
    for doc in docs:
        db_session.delete(doc)
    links = db_session.query(Link).filter_by(user_id=user.id).all()
    for link in links:
        db_session.delete(link)
    db_session.delete(user)
    db_session.commit()


def create_inactive_user(db_session: Session, email: str, password: str,
                         password_hash_algo: PasswordHashAlgo = User.DEFAULT_PASSWORD_HASH_ALGO) -> User:
    """Create an account which has not been activated.
    Return the user object (model)
    :param password_hash_algo:  This parameter exists for testing
        In all cases outside of testing, this should be set to User.DEFAULT_PASSWORD_HASH_ALGO
    """
    assert isinstance(email, six.text_type), "Type of email is %s" % type(email)
    assert isinstance(password, six.text_type), "Type of password is %s" % type(password)
    salt = get_salt(SALT_SIZE)
    assert isinstance(salt, bytes), "Type of salt is %s" % type(salt)
    password_hash = get_hashed_password(password, salt, password_hash_algo)
    assert isinstance(password_hash, bytes)
    user = User()
    user.email = email
    # the hashed password is a binary string, so have to convert to unicode
    # will be unicode when it comes out of DB anyway
    user.password = password_hash.decode("utf-8")
    user.password_hash_algo = password_hash_algo
    assert isinstance(user.password, six.text_type)
    # even though it would make a lot of sense to store the salt as a binary string, in reality it is stored in unicode
    user.salt = salt.decode("utf-8")
    user.active = False
    # necessary to get user ID
    db_session.add(user)
    db_session.commit()
    return user


def insert_entry_for_user(db_session: Session, dec_entry: dict,
                          user_id: int, user_key: str,
                          version: int = DEFAULT_ENTRY_VERSION) -> Entry:
    assert isinstance(user_id, int)
    assert isinstance(user_key, six.text_type)
    assert isinstance(version, int)
    entry = encrypt_entry(user_key, dec_entry, version=version)
    insert_new_entry(db_session, entry, user_id)
    db_session.commit()
    return entry


def insert_link_for_user(db_session: Session, dec_link: dict,
                         user_id: int, user_key: str) -> Link:
    assert isinstance(user_id, int)
    assert isinstance(user_key, six.text_type)
    link = encrypt_link(user_key, dec_link)
    insert_new_link(db_session, link, user_id)
    db_session.commit()
    return link


def encrypt_link(user_key: str, dec_link: dict) -> Link:
    assert isinstance(user_key, six.text_type)
    assert isinstance(dec_link, dict)
    link = Link()
    link.encrypt(user_key, dec_link)
    # NOTE: DO NOT save the link here
    return link


def insert_new_link(session: Session, link: Link, user_id: int) -> None:
    link.user_id = user_id
    session.add(link)


def insert_new_entry(session: Session, entry: Entry, user_id: int) -> None:
    entry.user_id = user_id
    session.add(entry)


def encrypt_entry(user_key: str, dec_entry: dict,
                  version: int = DEFAULT_ENTRY_VERSION) -> Entry:
    """
    A different KDF key is used for each entry.
    This is equivalent to salting the entry.
    :param dec_entry:   A dictionary representing the decrypted entry
        Required keys depend on entry version
    :param user_key:    A string representing the user's key
    :return:            Entry object
    """
    assert isinstance(user_key, six.text_type)
    assert isinstance(dec_entry, dict)
    assert isinstance(version, int)
    entry = None
    if version == 5:
        entry = Entry_v5()
    elif version == 4:
        entry = Entry_v4()
    elif version == 3:
        entry = Entry_v3()
    else:
        raise Exception("We do not support encrypting very old entries (version specified = {})".format(version))
    entry.encrypt(user_key, dec_entry)
    return entry


def edit_link(session: Session, link_id: int, user_key: str, edited_link: dict, user_id: int) -> Link:
    """
    Try to edit the link with ID <link_id>. Commit changes to DB.
    Check first if the link belongs to the current user
    :param session:        Database session
    :param link_id:        ID of an existing link to be edited
    :param user_key:       Password of the logged-in user
    :param edited_link:    Dictionary of changes to the link
    :param user_id:        ID of the user
    :return:               Newly edited link
    :rtype:                Link
    """
    link = session.query(Link).filter_by(id=link_id).one()
    assert link.user_id == user_id
    dec_link = {
        "service_name": edited_link["service_name"],
        "link": edited_link["link"],
    }
    # do not add l2 to session, it's just a placeholder
    l2 = encrypt_link(user_key, dec_link)
    # update encrypted fields
    link.contents = l2.contents
    # update metadata
    link.kdf_salt = l2.kdf_salt
    # and save `links`; discard l2
    session.commit()
    return link


def edit_entry(session: Session, entry_id: int, user_key: str, edited_entry: dict, user_id: int) -> Entry:
    """
    Try to edit the entry with ID <entry_id>. Commit changes to DB.
    Check first if the entry belongs to the current user
    DO NOT bump the version
    :param session:         Database session
    :param entry_id:        ID of an existing entry to be edited
    :param user_key:        Password of the logged-in user
    :param edited_entry:    Dictionary of changes to the entry
    :param user_id:         ID of the user
    :return:                Newly edited entry
    :rtype:                 Entry
    """
    entry = session.query(Entry).filter_by(id=entry_id).one()
    assert entry.user_id == user_id
    dec_entry = {
        "account": edited_entry["account"],
        "username": edited_entry["username"],
        "password": edited_entry["password"],
        "extra": (edited_entry["extra"] or ""),
        "has_2fa": edited_entry["has_2fa"]
    }
    # do not add e2 to session, it's just a placeholder
    e2 = encrypt_entry(user_key, dec_entry,
                       version=entry.version)
    # update those fields that the user might have changed
    entry.account = e2.account
    entry.username = e2.username
    entry.password = e2.password
    entry.extra = e2.extra
    entry.has_2fa = e2.has_2fa
    try:
        entry.contents = e2.contents
    except AttributeError:
        # this is fine, just means we're editing an old entry
        pass
    # update those parameters which might have changed on encryption
    entry.iv = e2.iv
    entry.key_salt = e2.key_salt
    session.commit()
    return entry


def get_services_map(session: Session) -> Dict[str, Any]:
    services = session.query(Service).all()
    d = {}
    for service in services:
        d[service.name.lower()] = {
            "service": service.name,
            "has_two_factor": service.has_two_factor,
            "link": service.link
        }
    return d


def encrypt_document(session: Session, user_id: int, master_key: str,
                     document_name: str, document) -> EncryptedDocument:
    """
    Create an encrypted document, fill in the fields, and save in the database
    :param session: database session, NOT flask session
    :param document: contents of the document
    :rtype:             EncryptedDocument
    """
    assert isinstance(user_id, int)
    assert isinstance(master_key, six.text_type)
    assert isinstance(document_name, six.text_type)
    doc = DecryptedDocument(document_name, document)
    return insert_document_for_user(session, doc, user_id, master_key)


def insert_document_for_user(session: Session, decrypted_document, user_id, master_key) -> EncryptedDocument:
    """
    :param session: database session, NOT flask session
    :param decrypted_document: DecryptedDocument
    :param master_key: unicode
    :param user_id: int
    :rtype:                         EncryptedDocument
    """
    assert isinstance(decrypted_document, DecryptedDocument)
    assert isinstance(user_id, int)
    assert isinstance(master_key, six.text_type)
    extended_key, extension_params = DecryptedDocument.extend_key(master_key)
    assert isinstance(extended_key, bytes)
    enc_doc = decrypted_document.encrypt(extended_key)
    enc_doc.key_salt = base64_encode(extension_params["kdf_salt"]).decode("utf-8")
    assert isinstance(enc_doc.key_salt, six.text_type)
    enc_doc.user_id = user_id
    assert isinstance(enc_doc.user_id, int)
    session.add(enc_doc)
    session.commit()
    return enc_doc
