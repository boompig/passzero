import logging
import time
from typing import Any, Dict, List, Optional, Tuple, TypedDict

from sqlalchemy import and_, func
from sqlalchemy.orm.exc import NoResultFound
from sqlalchemy.orm.session import Session
from sqlalchemy.sql.expression import asc

from passzero import audit
from passzero import email as pz_email
from passzero.config import DEFAULT_ENTRY_VERSION, ENTRY_LIMITS, SALT_SIZE
from passzero.crypto_utils import (PasswordHashAlgo, get_hashed_password,
                                   get_salt)
from passzero.models import (ApiToken, AuthToken, DecryptedDocument,
                             EncryptedDocument, EncryptionKeys,
                             EncryptionKeysDB_V1, Entry, Entry_v2, Entry_v3,
                             Entry_v4, Entry_v5, Link, Service, User)
from passzero.utils import base64_encode

UPDATE_LIMIT = 60
# we are using this form of logging here
# because we might not be in a flask context when calling functions in this file
logger = logging.getLogger(__name__)


class UserNotAuthorizedError(Exception):
    pass


class InternalServerError(Exception):
    """This exception is used when some internal state in the server is not consistent.
    Done so we can give an opaque message to the client while logging the problem at the server."""
    pass


class EntryValidationError(Exception):
    """Exception when we fail to validate some aspects of user-provided entry"""
    pass


class UserExistsError(Exception):
    """The account already exists. Raise the exception with a helpful message."""
    pass


class EmailSendError(Exception):
    """Failed to send an email"""
    pass


def create_new_account(db_session: Session, email: str, password: str) -> Tuple[User, AuthToken]:
    """Create a new account. Perform all steps necessary including sending an email.
    The newly created account will be inactive.
    If a new account is created, return the newly created user.
    In all other cases raise an error.
    :throws UserExistsError: make sure to read the error message
    :throws EmailSendError:
    """
    try:
        user = get_account_with_email(db_session, email)
        # this is the bad case
        if user.active:
            raise UserExistsError(
                "an account with this email address already exists"
            )
        else:
            raise UserExistsError(
                "This account has already been created. Check your inbox for a confirmation email."
            )
    except NoResultFound:
        logger.info("Creating account for user with email %s...", email)
        # this is the good case
        token = AuthToken()
        token.random_token()
        if pz_email.send_confirmation_email(email, token.token):
            # this also creates a number of backend structures
            user = create_inactive_user(
                db_session,
                email,
                password,
            )
            token.user_id = user.id
            # now add token
            db_session.add(token)
            db_session.commit()
            logger.info(
                "Successfully created account with email %s", email
            )
            return (user, token)
        else:
            raise EmailSendError("failed to send email")


def activate_account(db_session: Session, user: User):
    """Set the user to active and commit changes"""
    user.active = True
    db_session.add(user)
    db_session.commit()


class PasswordStrengthAuditEntry(TypedDict):
    id: int
    account: str
    score: int
    feedback: str


def password_strength_scores(email: str, dec_entries: list) -> List[PasswordStrengthAuditEntry]:
    dec_entries_json = []
    for entry in dec_entries:
        results = audit.password_strength(entry["password"], user_inputs=[
            entry["account"], entry["username"], email
        ])
        d = PasswordStrengthAuditEntry(
            id=entry["id"],
            account=entry["account"],
            score=results["score"],
            feedback=" ".join(results["feedback"]["suggestions"]),
        )
        if entry["password"] == "" or entry["password"] == "-":
            continue
        dec_entries_json.append(d)
    return dec_entries_json


class TwoFactorAuditEntry(TypedDict):
    service_has_2fa: bool
    entry_has_2fa: bool
    entry_id: int


def two_factor_audit(db_session: Session, user_id: int) -> Dict[str, TwoFactorAuditEntry]:
    """
    :return a map from entry *account names* to an audit entry
    """
    entries = get_entries(db_session, user_id)
    services_map = get_services_map(db_session)
    two_factor_map = {}
    for entry in entries:
        account = entry.account.lower()
        two_factor_map[entry.account] = TwoFactorAuditEntry(
            service_has_2fa=services_map.get(account, {}).get("has_two_factor", False),
            entry_has_2fa=entry.has_2fa,
            entry_id=entry.id,
        )
    return two_factor_map


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
    assert isinstance(key, str)
    # return _decrypt_entries_multiprocess(entries, key)
    return _decrypt_entries_single_thread(entries, key)


def get_entries(db_session: Session, user_id: int) -> List[Entry]:
    """Return a list of entries without decrypting them.
    Ordered by account name.
    Do not return the pinned entry."""
    assert isinstance(user_id, int)
    return db_session.query(Entry)\
        .filter_by(user_id=user_id, pinned=False)\
        .order_by(asc(func.lower(Entry.account)))\
        .all()


def get_links(db_session: Session, user_id: int) -> List[Link]:
    """Return a list of links without decrypting them.
    Ordered by ID."""
    assert isinstance(user_id, int)
    return db_session.query(Link)\
        .filter_by(user_id=user_id)\
        .order_by(Link.id.asc())\
        .all()


def get_link_by_id(db_session: Session, user_id: int, link_id: int) -> Optional[Link]:
    """Return link with given ID.
    If it doesn't belong to the user return None
    If it doesn't exist also return None"""
    try:
        link = db_session.query(Link).filter_by(id=link_id).one()
        if link.user_id != user_id:
            return None
        return link
    except NoResultFound:
        return None


def get_account_with_email(db_session: Session, email: str) -> User:
    assert isinstance(email, str)
    return db_session.query(User).filter_by(email=email).one()


def get_account_with_username(db_session: Session, username: str) -> User:
    assert isinstance(username, str)
    return db_session.query(User).filter_by(username=username).one()


def delete_entry(db_session: Session, entry_id: int, user_id: int, user_key: str) -> None:
    """
    :throws NoResultFound: When entry_id does not correspond to a valid entry
    :throws AssertionError: When entry_id refers to an entry owned by another user
                            or when it is a pinned entry
    """
    entry = db_session.query(Entry).filter_by(id=entry_id).one()
    assert entry.user_id == user_id
    assert not entry.pinned, "Cannot delete a pinned entry using this method"
    db_session.delete(entry)
    # remove corresponding decryption key
    _delete_encryption_key(db_session, user_id, user_key, entry_id, elem_type="entry")
    db_session.commit()


def delete_link(db_session: Session, link_id: int, user_id: int, user_key: str) -> None:
    """
    :throws NoResultFound: When link_id does not correspond to a valid link
    :throws UserNotAuthorizedError: When link does not belong to that user
    """
    # may throw NoResultFound -> should be caught by parent
    link = db_session.query(Link).filter_by(id=link_id).one()
    if link.user_id != user_id:
        raise UserNotAuthorizedError("The given link does not belong to this user")
    assert link.user_id == user_id
    # these operations *together* form a transaction
    db_session.delete(link)
    _delete_encryption_key(db_session, user_id, user_key, link_id, elem_type="link")
    db_session.commit()


def delete_all_entries(db_session: Session, user: User, user_key: str) -> None:
    """This does not delete the pinned entry.
    To use this function, the user's current master password must be known.
    :param user_key:    The user's master password. Must be correc.t
    """
    entries = db_session.query(Entry).filter(and_(
        Entry.user_id == user.id,
        Entry.pinned == False,  # noqa
    )).all()
    # first delete the entries from the keys DB
    # EncryptionKeys guaranteed to exist
    enc_keys_db = db_session.query(EncryptionKeys).filter_by(user_id=user.id).one()
    keys_db = enc_keys_db.decrypt(user_key)
    for entry in entries:
        try:
            # entry ID guaranteed to exist in EncryptionKeys
            assert str(entry.id) in keys_db["entry_keys"]
            del keys_db["entry_keys"][str(entry.id)]
        except AssertionError:
            logger.error("Entered inconsistent state in keys DB: entry %d not found", entry.id)
    # re-encrypt the database
    enc_keys_db.encrypt(user_key, keys_db)
    # re-add it since it has been modified
    db_session.add(enc_keys_db)
    # now delete the entries
    entries_q = db_session.query(Entry).filter(and_(
        Entry.user_id == user.id,
        Entry.pinned == False,  # noqa
    ))
    entries_q.delete()
    # commit everything as a single transaction
    db_session.commit()


def delete_account(db_session: Session, user: User) -> None:
    """Delete the given user from the database.
    Also delete all entries associated with that user
    Also delete all documents associated with that user
    Delete all data for that user across all tables"""
    entries_q = db_session.query(Entry).filter_by(user_id=user.id)
    entries_q.delete()
    auth_tokens_q = db_session.query(AuthToken).filter_by(user_id=user.id)
    auth_tokens_q.delete()
    api_tokens_q = db_session.query(ApiToken).filter_by(user_id=user.id)
    api_tokens_q.delete()
    docs_q = db_session.query(EncryptedDocument).filter_by(user_id=user.id)
    docs_q.delete()
    links_q = db_session.query(Link).filter_by(user_id=user.id)
    links_q.delete()
    enc_keys_db = db_session.query(EncryptionKeys).filter_by(user_id=user.id).one_or_none()
    if enc_keys_db:
        db_session.delete(enc_keys_db)
    db_session.delete(user)
    db_session.commit()


def recover_account_confirm(db_session: Session, user: User, new_master_password: str) -> None:
    assert isinstance(new_master_password, str), "Type of password is %s" % type(new_master_password)

    # delete subordinate entities such as entries, API tokens, documents, links, and encryption keys
    entries_q = db_session.query(Entry).filter_by(user_id=user.id)
    entries_q.delete()
    # NOTE: we do not delete auth tokens here
    api_tokens_q = db_session.query(ApiToken).filter_by(user_id=user.id)
    api_tokens_q.delete()
    docs_q = db_session.query(EncryptedDocument).filter_by(user_id=user.id)
    docs_q.delete()
    links_q = db_session.query(Link).filter_by(user_id=user.id)
    links_q.delete()
    enc_keys_db = db_session.query(EncryptionKeys).filter_by(user_id=user.id).one_or_none()
    if enc_keys_db:
        db_session.delete(enc_keys_db)

    # however we are *not* deleting the user
    # instead we are changing the password
    salt = get_salt(SALT_SIZE)
    assert isinstance(salt, bytes), "Type of salt is %s" % type(salt)
    hash_algo = User.DEFAULT_PASSWORD_HASH_ALGO
    password_hash = get_hashed_password(new_master_password, salt, hash_algo)
    assert isinstance(password_hash, bytes)
    # the hashed password is a binary string, so have to convert to unicode
    # will be unicode when it comes out of DB anyway
    user.password = password_hash.decode("utf-8")
    user.password_hash_algo = hash_algo
    assert isinstance(user.password, str)
    # even though it would make a lot of sense to store the salt as a binary string, in reality it is stored in unicode
    user.salt = salt.decode("utf-8")
    db_session.add(user)

    # add additional structures
    _create_empty_encryption_key_db(db_session, user, new_master_password)
    # necessary to commit so we can add pinned entry to it
    db_session.commit()

    create_pinned_entry(db_session, user.id, new_master_password)
    db_session.commit()


def create_pinned_entry(session: Session, user_id: int, master_password: str) -> None:
    """NOTE: The pinned entry is added to the session, but the session is *not* committed here"""
    assert isinstance(user_id, int), f"Expected user_id to be of type int, was of type {type(user_id)}"
    assert isinstance(master_password, str)
    # is there already a pinned entry?
    pinned_entry = session.query(Entry).filter(and_(
        Entry.user_id == user_id,
        Entry.pinned == True  # noqa
    )).one_or_none()
    if pinned_entry:
        # delete the old pinned entry before we create a new one
        session.delete(pinned_entry)

    dec_entry = {
        "account": "sanity",
        "username": "sanity",
        "password": "sanity",
        "extra": "sanity",
        "has_2fa": False
    }
    new_entry, _ = encrypt_entry(master_password, dec_entry)
    new_entry.pinned = True
    insert_new_entry(session, new_entry, user_id)


def create_inactive_user(db_session: Session, email: str, password: str,
                         password_hash_algo: PasswordHashAlgo = User.DEFAULT_PASSWORD_HASH_ALGO) -> User:
    """Create an account which has not been activated. Commit the user and all associated data structures.
    Return the user object (model)
    :param password_hash_algo:  This parameter exists for testing
        In all cases outside of testing, this should be set to User.DEFAULT_PASSWORD_HASH_ALGO
    """
    assert isinstance(email, str), "Type of email is %s" % type(email)
    assert isinstance(password, str), "Type of password is %s" % type(password)
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
    assert isinstance(user.password, str)
    # even though it would make a lot of sense to store the salt as a binary string, in reality it is stored in unicode
    user.salt = salt.decode("utf-8")
    user.active = False
    # necessary to get user ID
    db_session.add(user)
    # commit here to get user ID
    db_session.commit()

    # add additional structures
    _create_empty_encryption_key_db(db_session, user, password)
    # necessary to commit so we can add pinned entry to it
    db_session.commit()

    create_pinned_entry(db_session, user.id, password)
    db_session.commit()

    return user


def _create_empty_encryption_key_db(db_session: Session, user: User, user_key: str) -> EncryptionKeys:
    """Instantiate an empty encryption keys database for the given user.
    NOTE: It's added to the session but is *not* committed here
    :return: Return the newly created encryption keys database
    """
    keys_db = EncryptionKeysDB_V1(
        entry_keys={},
        link_keys={},
        # need to specify these fields for mypy
        # they get overwritten in .encrypt method
        version=1,
        user_id=user.id,
        id=None,
    )
    enc_keys_db = EncryptionKeys()
    enc_keys_db.encrypt(user_key, keys_db)
    enc_keys_db.user_id = user.id
    db_session.add(enc_keys_db)
    return enc_keys_db


def validate_user_supplied_entry(dec_entry: dict):
    """
    On success, nothing happens
    On error, throw EntryValidationError
    """
    # check the length of string fields
    # note that these might not be supplied, or might be set to None
    for field, max_length in ENTRY_LIMITS.items():
        val = dec_entry.get(field, None)
        if val is not None:
            if not isinstance(dec_entry[field], str):
                raise EntryValidationError(f"entry field {field} must be a string")
            if len(dec_entry[field]) > max_length:
                raise EntryValidationError(f"entry field {field} cannot be longer than {max_length} characters")


def insert_entry_for_user(db_session: Session, dec_entry: dict,
                          user_id: int, user_key: str,
                          version: int = DEFAULT_ENTRY_VERSION,
                          prevent_deprecated_versions: bool = True) -> Entry:
    """This is the entry-point for creating new entries from API methods.
    The session is committed in this method.
    The entry must conform to the entry spec:
        - account: string (required)
        - username: string (required)
        - password: string (required)
        - has_2fa: boolean (required)
        - extra: string (optional)
    :throws EntryValidationError: If some basic checks on the user-provided entry fails
    """
    assert isinstance(user_id, int)
    assert isinstance(user_key, str)
    assert isinstance(version, int)

    # validate the user-provided entry
    validate_user_supplied_entry(dec_entry)

    entry, entry_key = encrypt_entry(user_key, dec_entry, version=version,
                                     prevent_deprecated_versions=prevent_deprecated_versions)
    insert_new_entry(db_session, entry, user_id)
    # double commit is intentional. 1st one gets entry.id
    db_session.commit()
    _insert_encryption_key(db_session, user_id, user_key, entry.id, entry_key, elem_type="entry")
    # second one commits the encryption key
    db_session.commit()
    return entry


def _insert_encryption_key(db_session: Session, user_id: int, user_key: str, elem_id: int, symmetric_key: bytes,
                           elem_type: str) -> None:
    """Insert the entry key. Entry user_id and is must be set at this point.
    We assume that the entry already exists in the DB.
    This method also works if the key for the entry already exists and we want to overwrite it.
    Do not commit the session here.
    :param elem_type: What type of element this key belongs to (entry, link, etc.)
    """
    assert isinstance(user_id, int)
    assert isinstance(elem_id, int)
    assert elem_type in ["entry", "link"]
    # EncryptionKeys database guaranteed to exist by this point
    enc_keys_db = db_session.query(EncryptionKeys).filter_by(user_id=user_id).one_or_none()
    if enc_keys_db is None:
        # this is a legacy compatibility for users created before encryption databases
        logger.warning("No encryption keys database found for user %d, creating", user_id)
        user = db_session.query(User).filter_by(id=user_id).one()
        enc_keys_db = _create_empty_encryption_key_db(db_session, user, user_key)

    keys_db = enc_keys_db.decrypt(user_key)
    k = {
        "entry": "entry_keys",
        "link": "link_keys",
    }[elem_type]
    keys_db[k][str(elem_id)] = {
        # we store the keys in binary for a more compact representation
        "key": symmetric_key,
        # similarly with the timestamp, we store integers for a more compact repr.
        "last_modified": int(time.time()),
    }
    # re-encrypt
    enc_keys_db.encrypt(user_key, keys_db)
    db_session.add(enc_keys_db)


def _update_encryption_key(db_session: Session, user_id: int, user_key: str, elem_id: int, new_symmetric_key: bytes,
                           elem_type: str) -> None:
    """Encryption key is added but not committed
    """
    assert isinstance(user_id, int), "user_id must be an integer"
    assert isinstance(elem_id, int), "elem_id must be an integer"
    assert elem_type in ["entry", "link"], "elem_type must be one of entry, link"
    enc_keys_db = db_session.query(EncryptionKeys).filter_by(user_id=user_id).one_or_none()
    if enc_keys_db is None:
        # this is a legacy compatibility for users created before encryption databases
        logger.warning("No encryption keys database found for user %d, creating", user_id)
        user = db_session.query(User).filter_by(id=user_id).one()
        enc_keys_db = _create_empty_encryption_key_db(db_session, user, user_key)

    keys_db = enc_keys_db.decrypt(user_key)
    k = {
        "entry": "entry_keys",
        "link": "link_keys",
    }[elem_type]
    if str(elem_id) in keys_db[k]:
        # should be inside relevant keys collection
        keys_db[k][str(elem_id)]["key"] = new_symmetric_key
        keys_db[k][str(elem_id)]["last_modified"] = int(time.time())
        enc_keys_db.encrypt(user_key, keys_db)
        # re-add it to the session
        db_session.add(enc_keys_db)
    else:
        logger.warning("Element (type %s, ID %d) not found in encryption keys database during update, inserting",
                       elem_type, elem_id)
        _insert_encryption_key(db_session, user_id, user_key, elem_id, new_symmetric_key, elem_type)


def _delete_encryption_key(db_session: Session, user_id: int, user_key: str, elem_id: int,
                           elem_type: str) -> None:
    """Added but not committed"""
    assert isinstance(user_id, int)
    assert isinstance(elem_id, int)
    enc_keys_db = db_session.query(EncryptionKeys).filter_by(user_id=user_id).one_or_none()
    if enc_keys_db is None:
        # this is a legacy compatibility for users created before encryption databases
        logger.warning("No encryption keys database found for user %d, creating", user_id)
        user = db_session.query(User).filter_by(id=user_id).one()
        enc_keys_db = _create_empty_encryption_key_db(db_session, user, user_key)

    keys_db = enc_keys_db.decrypt(user_key)
    # relevant entry *must* be present
    k = {
        "entry": "entry_keys",
        "link": "link_keys",
    }[elem_type]
    if str(elem_id) in keys_db[k]:
        del keys_db[k][str(elem_id)]
        # re-encrypt the database
        enc_keys_db.encrypt(user_key, keys_db)
        # re-add it since it has been modified
        db_session.add(enc_keys_db)
    else:
        logger.warning("Element (type %s, ID %d) not found in encryption keys database during deletion, ignoring",
                       elem_type, elem_id)


def insert_link_for_user(db_session: Session, dec_link: dict,
                         user_id: int, user_key: str) -> Link:
    assert isinstance(user_id, int)
    assert isinstance(user_key, str)
    link, link_key = encrypt_link(user_key, dec_link)
    insert_new_link(db_session, link, user_id)
    # make sure link has an ID
    db_session.commit()
    _insert_encryption_key(db_session, user_id, user_key, link.id, link_key, elem_type="link")
    # second commit commits encryption key
    db_session.commit()
    return link


def encrypt_link(user_key: str, dec_link: dict) -> Tuple[Link, bytes]:
    assert isinstance(user_key, str)
    assert isinstance(dec_link, dict)
    link = Link()
    link_key = link.encrypt(user_key, dec_link)
    # NOTE: DO NOT save the link here
    return link, link_key


def insert_new_link(session: Session, link: Link, user_id: int) -> None:
    # NOTE: session is not committed here
    link.user_id = user_id
    session.add(link)


def insert_new_entry(session: Session, entry: Entry, user_id: int) -> None:
    """Set the entry's user_id appropriately and add it to the session
    NOTE: DB session is not committed here"""
    entry.user_id = user_id
    session.add(entry)


def encrypt_entry(user_key: str, dec_entry: dict,
                  version: int = DEFAULT_ENTRY_VERSION,
                  prevent_deprecated_versions: bool = True) -> Tuple[Entry, bytes]:
    """
    A different KDF key is used for each entry.
    This is equivalent to salting the entry.
    :param dec_entry:   A dictionary representing the decrypted entry
        Required keys depend on entry version
    :param user_key:    A string representing the user's key
    :return:            Entry object
    """
    assert isinstance(user_key, str)
    assert isinstance(dec_entry, dict)
    assert isinstance(version, int)
    if version < 3 and prevent_deprecated_versions:
        raise Exception(f"We do not support encrypting very old entries (version specified = {version})")
    if "extra" not in dec_entry:
        dec_entry["extra"] = ""
    entry = None
    if version == 5:
        entry = Entry_v5()
    elif version == 4:
        entry = Entry_v4()
    elif version == 3:
        entry = Entry_v3()
    elif version == 2:
        entry = Entry_v2()
    elif version == 1:
        entry = Entry()
    else:
        raise Exception(f"Invalid entry version: {version}")
    assert entry is not None
    entry_key = entry.encrypt(user_key, dec_entry)
    return entry, entry_key


def update_entry_versions_for_user(db_session: Session, user_id: int, master_key: str,
                                   limit: Optional[int] = UPDATE_LIMIT) -> int:
    """"
    Update the versions of entries to the latest version
    Return the number of entries updated
    """
    n = 0
    latest_version = 5
    if limit is None or limit > UPDATE_LIMIT:
        limit = UPDATE_LIMIT
    entries = db_session.query(Entry).filter(and_(
        Entry.user_id == user_id,
        Entry.pinned == False,  # noqa
        Entry.version < latest_version
    )).all()
    enc_keys_db = db_session.query(EncryptionKeys).filter_by(user_id=user_id).one()
    keys_db = enc_keys_db.decrypt(master_key)
    for entry in entries:
        dec_entry = entry.decrypt(master_key)  # type: dict
        e2 = Entry_v5()
        new_entry_key = e2.encrypt(master_key, dec_entry)
        e2.user_id = user_id
        # reuse ID from deleted entry
        e2.id = entry.id
        db_session.delete(entry)
        db_session.add(e2)
        # update the keys database
        keys_db["entry_keys"][str(e2.id)]["key"] = new_entry_key
        n += 1
        if n == limit:
            break
    # re-encrypt
    enc_keys_db.encrypt(master_key, keys_db)
    # make sure updated DB is in the session
    db_session.add(enc_keys_db)
    db_session.commit()
    return n


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
    assert link.user_id == user_id, "The given link does not belong to the provided user ID"
    dec_link = {
        "service_name": edited_link["service_name"],
        "link": edited_link["link"],
    }
    # this method should replace the correct fields
    new_link_key = link.encrypt(user_key, dec_link)
    session.commit()
    assert link.id == link_id, "The link's ID has changed unexpectedly during editing"
    _update_encryption_key(session, user_id, user_key, link_id, new_link_key, elem_type="link")
    session.commit()
    return link


def edit_entry(session: Session, entry_id: int, user_key: str, edited_entry: dict, user_id: int) -> Entry:
    """
    Try to edit the entry with ID <entry_id>. Commit changes to DB.
    Check first if the entry belongs to the current user
    DO NOT bump the entry's version
    :param session:         Database session
    :param entry_id:        ID of an existing entry to be edited
    :param user_key:        Password of the logged-in user
    :param edited_entry:    Dictionary of changes to the entry
    :param user_id:         ID of the user
    :return:                Newly edited entry
    :rtype:                 Entry
    :throws AssertionError: If the entry does not belong to the user or if it is pinned
    :throws EntryValidationError: If one or more of the entry's fields fail validation
    """
    validate_user_supplied_entry(edited_entry)
    try:
        entry = session.query(Entry).filter_by(id=entry_id).one()
        assert entry.user_id == user_id
        assert not entry.pinned, "Cannot edit a pinned entry using this method"
        dec_entry = {
            "account": edited_entry["account"],
            "username": edited_entry["username"],
            "password": edited_entry["password"],
            "extra": (edited_entry["extra"] or ""),
            "has_2fa": edited_entry["has_2fa"]
        }
        # this method should replace the correct fields
        new_entry_key = entry.encrypt(user_key, dec_entry)
        # commit the entry back to the database
        session.commit()
        # entry ID should remain the same
        assert entry.id == entry_id
        _update_encryption_key(session, user_id, user_key, entry_id, new_entry_key, elem_type="entry")
        session.commit()
        return entry
    except NoResultFound as e:
        # catch the error to log something here
        logger.error("User requested to edit entry %d but that entry does not exist", entry_id)
        raise e


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


def get_document_by_id(db_session: Session, user_id: int, document_id: int) -> Optional[EncryptedDocument]:
    """Return document with given ID.
    If it doesn't belong to the user return None
    If it doesn't exist also return None"""
    try:
        doc = db_session.query(EncryptedDocument).filter_by(id=document_id).one()
        if doc.user_id != user_id:
            return None
        return doc
    except NoResultFound:
        return None


def encrypt_document(session: Session, user_id: int, master_key: str,
                     document_name: str, mimetype: str, document) -> EncryptedDocument:
    """
    Create an encrypted document, fill in the fields, and save in the database
    :param session: database session, NOT flask session
    :param document: contents of the document
    :rtype:             EncryptedDocument
    """
    assert isinstance(user_id, int)
    assert isinstance(master_key, str)
    assert isinstance(document_name, str)
    assert isinstance(mimetype, str) and mimetype is not None
    doc = DecryptedDocument(document_name, mimetype, document)
    assert doc.mimetype is not None
    return insert_document_for_user(session, doc, user_id, master_key)


def insert_document_for_user(session: Session, decrypted_document: DecryptedDocument,
                             user_id: int, master_key: str) -> EncryptedDocument:
    """
    :param session: database session, NOT flask session
    :param decrypted_document: DecryptedDocument
    :param master_key: unicode
    :param user_id: int
    :rtype:                         EncryptedDocument
    """
    assert isinstance(decrypted_document, DecryptedDocument)
    assert isinstance(user_id, int)
    assert isinstance(master_key, str)
    extended_key, extension_params = DecryptedDocument.extend_key(master_key)
    assert isinstance(extended_key, bytes)
    enc_doc = decrypted_document.encrypt(extended_key)
    enc_doc.key_salt = base64_encode(extension_params["kdf_salt"]).decode("utf-8")
    assert isinstance(enc_doc.key_salt, str)
    enc_doc.user_id = user_id
    assert isinstance(enc_doc.user_id, int)
    session.add(enc_doc)
    session.commit()
    return enc_doc


def edit_document(session: Session, document_id: int, master_key: str,
                  form_data: dict, user_id: int) -> EncryptedDocument:
    """
    Try to edit the document with ID <document_id>. Commit changes to DB.
    Check first if the document belongs to the current user.
    :param session:         Database session
    :param document_id:     ID of existing document to be edited
    :param master_key:      Document decryption key
    :param form_data:       Dictionary of changes to the document
    :param user_id:         ID of the logged-in user
    :return:                Newly edited document
    :rtype:                 EncryptedDocument
    """
    assert isinstance(document_id, int)
    assert isinstance(master_key, str)
    assert isinstance(form_data, dict)
    assert isinstance(user_id, int)
    doc = session.query(EncryptedDocument).filter_by(id=document_id).one()  # type: EncryptedDocument
    if doc.user_id != user_id:
        raise UserNotAuthorizedError
    dec_doc = doc.decrypt(master_key)
    dec_doc.contents = form_data["contents"]
    dec_doc.name = form_data["name"]
    dec_doc.mimetype = form_data["mimetype"]
    # create a second encrypted document, which we are *not* saving
    extended_key, extension_params = DecryptedDocument.extend_key(master_key)
    enc_doc2 = dec_doc.encrypt(extended_key)
    # edit the existing encrypted document so ID will not change
    doc.document = enc_doc2.document
    doc.key_salt = base64_encode(extension_params["kdf_salt"]).decode("utf-8")
    doc.name = enc_doc2.name
    doc.mimetype = enc_doc2.mimetype
    # make sure that the updated document maintains the same ID
    assert doc.id == document_id
    session.commit()
    return doc
