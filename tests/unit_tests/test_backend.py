import logging
import os

import pytest
from passzero import backend
from passzero.app_factory import create_app
from passzero.backend import (create_inactive_user, decrypt_entries,
                              delete_account, delete_all_entries, get_entries,
                              get_services_map, insert_document_for_user,
                              insert_link_for_user,
                              password_strength_scores)
from passzero.change_password import change_password
from passzero.crypto_utils import PasswordHashAlgo
from passzero.models import (AuthToken, DecryptedDocument, EncryptedDocument,
                             Entry, Link, Service, User)
from passzero.models import db as _db
from sqlalchemy.orm.exc import NoResultFound

from passzero.models.encryption_keys import EncryptionKeys

from .utils import assert_decrypted_entries_equal, get_test_decrypted_entry

DB_FILENAME = "passzero.db"
DEFAULT_EMAIL = u"fake@fake.com"
DEFAULT_PASSWORD = u"fake password"


@pytest.fixture(scope="session")
def app(request):
    """Provide the fixture for the duration of the test, then tear it down"""
    # remove previous database if present
    if os.path.exists(DB_FILENAME):
        os.remove(DB_FILENAME)

    settings_override = {
        "SQLALCHEMY_DATABASE_URI": "sqlite:///%s" % DB_FILENAME
    }

    app = create_app(__name__, settings_override)
    ctx = app.app_context()
    ctx.push()

    def teardown():
        ctx.pop()

    request.addfinalizer(teardown)
    return app


@pytest.fixture(scope="session")
def db(app, request):
    if os.path.exists(DB_FILENAME):
        os.remove(DB_FILENAME)

    def teardown():
        _db.drop_all()
        if os.path.exists(DB_FILENAME):
            os.remove(DB_FILENAME)

    _db.app = app
    _db.create_all()

    request.addfinalizer(teardown)
    return _db


@pytest.fixture(scope="function")
def session(db, request):
    connection = db.engine.connect()
    transaction = connection.begin()

    options = dict(bind=connection)
    session = db.create_scoped_session(options=options)

    db.session = session

    def teardown():
        # I don't think this works completely
        transaction.rollback()

        # so have to manually clear users table
        session.query(User).delete()
        session.query(Entry).delete()
        session.query(Service).delete()
        session.query(AuthToken).delete()
        session.query(Link).delete()
        session.query(EncryptedDocument).delete()
        session.query(EncryptionKeys).delete()
        session.commit()

        connection.close()
        session.remove()

    request.addfinalizer(teardown)
    return session


def test_create_inactive_user_sha512(session):
    u1 = backend.create_inactive_user(session, DEFAULT_EMAIL, DEFAULT_PASSWORD,
                                      password_hash_algo=PasswordHashAlgo.SHA512)
    assert u1.id is not None
    u2 = backend.get_account_with_email(session, DEFAULT_EMAIL)
    assert u1.id == u2.id


def test_create_inactive_user_argon2(session):
    u1 = backend.create_inactive_user(session, DEFAULT_EMAIL, DEFAULT_PASSWORD,
                                      password_hash_algo=PasswordHashAlgo.Argon2)
    assert u1.id is not None
    u2 = backend.get_account_with_email(session, DEFAULT_EMAIL)
    assert u1.id == u2.id


def test_create_inactive_user(session):
    """This method makes sure that when we can create an inactive user, certain structures are created"""
    user = backend.create_inactive_user(session, DEFAULT_EMAIL, DEFAULT_PASSWORD)
    # we should be creating a pinned entry
    entries = session.query(Entry).filter_by(user_id=user.id).all()
    assert len(entries) == 1
    assert entries[0].pinned == True  # noqa
    # we should also be creating the encryption database
    enc_keys_dbs = session.query(EncryptionKeys).filter_by(user_id=user.id).all()
    assert len(enc_keys_dbs) == 1
    enc_keys_db = enc_keys_dbs[0]
    # make sure we can decrypt it
    keys_db = enc_keys_db.decrypt(DEFAULT_PASSWORD)
    keys_db["entry_keys"] == {}
    keys_db["link_keys"] == {}


def test_delete_account(session):
    email = u"fake@email.com"
    user_key = u"master"
    user = create_inactive_user(session, email, user_key)
    assert user.id is not None
    # add an entry to that account
    dec_entry_in = {
        "account": "a",
        "username": "u",
        "password": "p",
        "extra": "e",
        "has_2fa": True
    }
    backend.insert_entry_for_user(session, dec_entry_in, user.id, user_key)
    # add a document to that account
    dec_doc = DecryptedDocument(
        name="test doc",
        contents="hello",
        mimetype="text/plain"
    )
    insert_document_for_user(session, dec_doc, user.id, user_key)
    # add a link to that account
    dec_link = {
        "service_name": "link",
        "link": "some link"
    }
    insert_link_for_user(session, dec_link, user.id, user_key)
    # add an auth token to that account
    token = AuthToken(user_id=user.id)
    token.random_token()
    _db.session.add(token)
    _db.session.commit()
    delete_account(session, user)
    try:
        u2 = backend.get_account_with_email(session, email)
        # only printed on error
        print(u2)
        assert False
    except NoResultFound:
        assert True


def test_insert_entry_for_user(session):
    dec_entry_in = get_test_decrypted_entry()
    user_key = u"master key"
    backend.insert_entry_for_user(session, dec_entry_in, 1, user_key)
    # make sure the entry is inserted
    enc_entries = get_entries(session, 1)
    assert len(enc_entries) == 1
    dec_entries = decrypt_entries(enc_entries, user_key)
    assert len(dec_entries) == 1
    assert_decrypted_entries_equal(dec_entry_in, dec_entries[0])


def test_delete_all_entries(session):
    user_key = u"master key"
    user = create_inactive_user(session, u"fake@em.com",
                                user_key)
    for i in range(10):
        dec_entry_in = {
            "account": "a-%d" % i,
            "username": "u",
            "password": "p",
            "extra": "e",
            "has_2fa": False
        }
        backend.insert_entry_for_user(session, dec_entry_in,
                                      user.id, user_key)
    enc_entries = get_entries(session, user.id)
    assert len(enc_entries) == 10
    delete_all_entries(session, user, user_key)
    enc_entries = get_entries(session, user.id)
    assert len(enc_entries) == 0


def __encrypt_decrypt_entry(version: int):
    """
    Encrypt and decrypt an entry at specified version. Make sure the output matches the input"""
    # create multiple entries for this user
    dec_entry = get_test_decrypted_entry()
    user_key = u"test master key"
    entry, _ = backend.encrypt_entry(user_key, dec_entry, version=version)
    assert isinstance(entry, Entry)
    dec_entry_out = entry.decrypt(user_key)
    assert_decrypted_entries_equal(dec_entry_out, dec_entry)


def test_encrypt_decrypt_entry_v5():
    __encrypt_decrypt_entry(5)


def test_encrypt_decrypt_entry_v4():
    __encrypt_decrypt_entry(4)


def test_encrypt_decrypt_entry_v3():
    __encrypt_decrypt_entry(3)


def test_fail_encrypt_entry_v2():
    """Should fail to encrypt entry v2 because it's too old"""
    # create multiple entries for this user
    dec_entry = {
        "account": u"test account",
        "username": u"test username",
        "password": u"test password",
        "extra": u"test extra",
        "has_2fa": True,
    }
    user_key = u"test master key"
    try:
        backend.encrypt_entry(user_key, dec_entry, version=2)
    except Exception:
        pass
    else:
        assert False, "Should throw exception"


def __edit_entry(session, version):
    """
    Try to edit an existing v4 entry"""
    user_key = u"test master key"
    user = create_inactive_user(session, u"fake@fake.com", user_key)
    dec_entry = {
        "account": u"test account",
        "username": u"test username",
        "password": u"test password",
        "extra": u"test extra",
        "has_2fa": True,
    }
    entry = backend.insert_entry_for_user(
        session,
        dec_entry,
        user.id,
        user_key,
        version=version
    )
    # save this in case it changes
    entry_id = entry.id
    # edit the entry
    dec_entry["password"] = u"a new password"
    dec_entry["has_2fa"] = False
    dec_entry["username"] = u"a new username"
    # edit the entry
    edited_entry = backend.edit_entry(
        session,
        entry_id,
        user_key,
        dec_entry,
        entry.user_id
    )
    # make sure the metadata remains the same
    assert edited_entry.version == version
    assert edited_entry.id == entry_id
    assert edited_entry.user_id == user.id
    # make sure entry is actually edited
    dec_entry_out = edited_entry.decrypt(user_key)
    assert_decrypted_entries_equal(dec_entry, dec_entry_out)


# NOTE: v2 and v1 not tested for now

def test_edit_entry_v3(session):
    __edit_entry(session, version=3)


def test_edit_entry_v4(session):
    __edit_entry(session, version=4)


def test_edit_entry_v5(session):
    __edit_entry(session, version=5)


def test_update_entry_versions_for_user(session):
    user = create_inactive_user(session, DEFAULT_PASSWORD, DEFAULT_PASSWORD)
    # should start with no entries
    entries = backend.get_entries(session, user.id)
    assert entries == []
    # create an entry of each version
    num_entries_per_version = 5
    input_dec_entries = {}
    for version in [1, 2, 3, 4, 5]:
        for i in range(num_entries_per_version):
            j = version * num_entries_per_version + i
            dec_entry = get_test_decrypted_entry(j)
            # remove extra field on some entries
            if j % 2:
                dec_entry.pop("extra")
            e = backend.insert_entry_for_user(
                db_session=session,
                dec_entry=dec_entry,
                user_id=user.id,
                user_key=DEFAULT_PASSWORD,
                version=version,
                prevent_deprecated_versions=False
            )
            # ID should not change
            input_dec_entries[e.id] = dec_entry
    # run the update
    num_updated = backend.update_entry_versions_for_user(session, user.id, DEFAULT_PASSWORD)
    # version 5 entries should not be updated
    assert num_updated == num_entries_per_version * 4
    entries = backend.get_entries(session, user.id)
    assert len(entries) == num_entries_per_version * 5
    for entry in entries:
        assert entry.version == 5
        actual = entry.decrypt(DEFAULT_PASSWORD)
        # assumes that IDs are sequential in terms of insert order
        assert_decrypted_entries_equal(input_dec_entries[entry.id], actual)


def test_update_entry_versions_for_user_only_latest(session):
    user = create_inactive_user(session, DEFAULT_PASSWORD, DEFAULT_PASSWORD)
    # should start with no entries
    entries = backend.get_entries(session, user.id)
    assert entries == []
    dec_entry = get_test_decrypted_entry(0)
    backend.insert_entry_for_user(session, dec_entry, user.id, DEFAULT_PASSWORD)
    entries = backend.get_entries(session, user.id)
    assert len(entries) == 1
    num_updated = backend.update_entry_versions_for_user(session, user.id, DEFAULT_PASSWORD)
    assert num_updated == 0
    entries = backend.get_entries(session, user.id)
    assert len(entries) == 1


def test_update_entry_versions_for_user_no_entries(session):
    user = create_inactive_user(session, DEFAULT_PASSWORD, DEFAULT_PASSWORD)
    # should start with no entries
    entries = backend.get_entries(session, user.id)
    assert entries == []
    num_updated = backend.update_entry_versions_for_user(session, user.id, DEFAULT_PASSWORD)
    assert num_updated == 0
    entries = backend.get_entries(session, user.id)
    assert entries == []


def test_get_account_with_email(session):
    email = u"fake_email"
    password = u"fake password"
    created_user = create_inactive_user(session, email, password)
    assert isinstance(created_user, User)
    assert created_user.email == email
    # TODO this is not a test, just makes sure that nothing crashes
    user = backend.get_account_with_email(session, email)
    # print this out on error
    print(user)
    assert True


def test_change_password(session):
    """
    Technically this function does not belong here since it doesn't really test the backend.
    We are testing the change_password method of change_password module
    """
    old_pwd = u"hello"
    new_pwd = u"world"
    user = create_inactive_user(session, u"fake@fake.com", old_pwd)
    logging.info("Creating fake entries")
    dec_entries_in = {}
    for i in range(10):
        dec_entry_in = get_test_decrypted_entry(i)
        entry_id = backend.insert_entry_for_user(session, dec_entry_in,
                                                 user.id, old_pwd).id
        dec_entries_in[entry_id] = dec_entry_in
    enc_entries = get_entries(session, user.id)
    logging.info("Decrypting newly created entries")
    dec_entries = decrypt_entries(enc_entries, old_pwd)
    assert len(dec_entries) == 10
    logging.info("Changing password")
    change_password(session, user.id, old_pwd, new_pwd)
    logging.info("Password has changed")
    enc_entries = get_entries(session, user.id)
    dec_entries = decrypt_entries(enc_entries, new_pwd)
    for dec_entry_out in dec_entries:
        assert_decrypted_entries_equal(dec_entries_in[dec_entry_out["id"]], dec_entry_out)
    # make sure we can still decrypt the encryption keys database
    enc_keys_db = session.query(EncryptionKeys).filter_by(user_id=user.id).one()
    # this just tests whether we can in fact decrypt the database
    enc_keys_db.decrypt(new_pwd)


def test_password_strength_scores():
    email = "fake@foo.io"
    dec_entries = [get_test_decrypted_entry(i) for i in range(10)]
    for i, entry in enumerate(dec_entries):
        entry["id"] = i
    dec_entries.append({
        "id": 10,
        "account": "no password here",
        "username": "foo",
        "password": "-",
        "has_2fa": False,
    })
    scores = password_strength_scores(email, dec_entries)
    # check that the no-password account is ignored
    assert len(dec_entries) - 1 == len(scores)
    for entry, score in zip(dec_entries, scores):
        assert entry["account"] == score["account"]


def test_get_services_map(session):
    # insert a thingy
    session.add(Service(name="MyService"))
    session.commit()
    service_map = get_services_map(session)
    assert len(service_map) == 1
    service_map.get("MyService", None) is not None


def test_edit_document(session):
    user = create_inactive_user(session, DEFAULT_EMAIL, DEFAULT_PASSWORD)
    doc = DecryptedDocument(name="first.txt", mimetype="text/plain", contents=b"hello world")
    enc_doc = backend.encrypt_document(
        session,
        user.id,
        DEFAULT_PASSWORD,
        doc.name,
        doc.mimetype,
        doc.contents
    )
    assert enc_doc.id >= 1
    dec_doc_2 = DecryptedDocument(
        name="second.txt",
        mimetype="text/plain",
        contents=b"goodbye cruel world"
    )
    enc_doc_2 = backend.edit_document(
        session,
        document_id=enc_doc.id,
        master_key=DEFAULT_PASSWORD,
        form_data=dec_doc_2.__dict__,
        user_id=user.id
    )
    assert enc_doc.id == enc_doc_2.id
    out = enc_doc_2.decrypt(DEFAULT_PASSWORD)
    assert out.name == dec_doc_2.name
    assert out.mimetype == dec_doc_2.mimetype
    assert out.contents == dec_doc_2.contents


def test_edit_nonexistant_document(session):
    user = create_inactive_user(session, DEFAULT_EMAIL, DEFAULT_PASSWORD)
    doc = backend.get_document_by_id(session, user.id, 1)
    assert doc is None
    try:
        backend.edit_document(
            session,
            1,
            DEFAULT_PASSWORD,
            {
                "name": "test",
                "contents": b"hello world",
                "mimetype": "text/plain"
            },
            user.id
        )
        assert False
    except NoResultFound:
        assert True, "great"


def test_edit_not_your_document(session):
    user = create_inactive_user(session, DEFAULT_EMAIL, DEFAULT_PASSWORD)
    dec_doc = DecryptedDocument(
        name="test doc",
        contents=b"hello",
        mimetype="text/plain"
    )
    # deliberately users have the same password
    enc_doc = insert_document_for_user(session, dec_doc, user.id, DEFAULT_PASSWORD)
    user2 = create_inactive_user(session, "user2@fake.com", "fake password 2")
    try:
        backend.edit_document(
            session,
            enc_doc.id,
            DEFAULT_PASSWORD,
            {
                "name": "test",
                "contents": b"hello world",
                "mimetype": "text/plain"
            },
            user2.id
        )
        assert False
    except backend.UserNotAuthorizedError:
        assert True, "great"
