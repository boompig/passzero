import logging
import os

import pytest
from mock import MagicMock
from sqlalchemy.orm.exc import NoResultFound

from passzero.app_factory import create_app
from passzero.backend import (create_inactive_user, decrypt_entries,
                              delete_account, delete_all_entries,
                              get_account_with_email, get_entries,
                              get_services_map, insert_document_for_user,
                              insert_entry_for_user, password_strength_scores)
from passzero import backend
from passzero.change_password import change_password
from passzero.crypto_utils import PasswordHashAlgo
from passzero.models import DecryptedDocument, Entry, Service, User
from passzero.models import db as _db

DB_FILENAME = "passzero.db"


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
        session.commit()

        connection.close()
        session.remove()

    request.addfinalizer(teardown)
    return session


def test_create_inactive_user_sha512(session):
    email = u"fake@email.com"
    password = u"pwd"
    u1 = create_inactive_user(session, email, password, password_hash_algo=PasswordHashAlgo.SHA512)
    assert u1.id is not None
    u2 = get_account_with_email(session, email)
    assert u1.id == u2.id


def test_create_inactive_user_argon2(session):
    email = u"fake@email.com"
    password = u"pwd"
    u1 = create_inactive_user(session, email, password, password_hash_algo=PasswordHashAlgo.Argon2)
    assert u1.id is not None
    u2 = get_account_with_email(session, email)
    assert u1.id == u2.id


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
    insert_entry_for_user(session, dec_entry_in, user.id, user_key)
    # add a document to that account
    dec_doc = DecryptedDocument(
        name=u"test doc",
        contents="hello"
    )
    insert_document_for_user(session, dec_doc, user.id, user_key)
    delete_account(session, user)
    try:
        u2 = get_account_with_email(session, email)
        # only printed on error
        print(u2)
        assert False
    except NoResultFound:
        assert True


def test_insert_entry_for_user(session):
    dec_entry_in = {
        "account": "a",
        "username": "u",
        "password": "p",
        "extra": "e",
        "has_2fa": True
    }
    user_key = u"master key"
    insert_entry_for_user(session, dec_entry_in, 1, user_key)
    # make sure the entry is inserted
    enc_entries = get_entries(session, 1)
    assert len(enc_entries) == 1
    dec_entries = decrypt_entries(enc_entries, user_key)
    assert len(dec_entries) == 1
    for field in dec_entry_in:
        assert dec_entry_in[field] == dec_entries[0][field]


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
        insert_entry_for_user(session, dec_entry_in,
                user.id, user_key)
    enc_entries = get_entries(session, user.id)
    assert len(enc_entries) == 10
    delete_all_entries(session, user)
    enc_entries = get_entries(session, user.id)
    assert len(enc_entries) == 0


def __encrypt_decrypt_entry(version: int):
    """
    Encrypt and decrypt an entry at specified version. Make sure the output matches the input"""
    # create multiple entries for this user
    dec_entry = {
        "account": u"test account",
        "username": u"test username",
        "password": u"test password",
        "extra": u"test extra",
        "has_2fa": True,
    }
    user_key = u"test master key"
    entry = backend.encrypt_entry(user_key, dec_entry, version=version)
    assert isinstance(entry, Entry)
    dec_entry_again = entry.decrypt(user_key)
    fields = ["account", "username", "password", "extra", "has_2fa"]
    for field in fields:
        assert dec_entry_again[field] == dec_entry[field]


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
    except Exception as e:
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
        "tags": ["hello", "world"]
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
    entry_fields = ["account", "username", "password", "extra", "has_2fa"]
    for field in entry_fields:
        assert dec_entry[field] == dec_entry_out[field]


# NOTE: v2 and v1 not tested for now

def test_edit_entry_v3(session):
    __edit_entry(session, version=3)


def test_edit_entry_v4(session):
    __edit_entry(session, version=4)


def test_edit_entry_v5(session):
    __edit_entry(session, version=5)


def test_get_account_with_email():
    session = MagicMock()
    email = u"fake_email"
    password = u"fake password"
    created_user = create_inactive_user(session, email, password)
    assert isinstance(created_user, User)
    assert created_user.email == email
    # TODO this is not a test, just makes sure that nothing crashes
    user = get_account_with_email(session, email)
    # print this out on error
    print(user)
    assert True


def create_fake_entry(i):
    return {
        "account": "a-%d" % i,
        "username": "u",
        "password": "p",
        "extra": "e",
        "has_2fa": False
    }

def test_change_password(session):
    old_pwd = u"hello"
    new_pwd = u"world"
    user = create_inactive_user(session, u"fake@fake.com", old_pwd)
    logging.info("Creating fake users")
    for i in range(10):
        dec_entry_in = create_fake_entry(i)
        insert_entry_for_user(session, dec_entry_in,
                user.id, old_pwd)
    enc_entries = get_entries(session, user.id)
    logging.info("Decrypting newly created entries")
    dec_entries = decrypt_entries(enc_entries, old_pwd)
    assert len(dec_entries) == 10
    logging.info("Changing password")
    change_password(session, user.id, old_pwd, new_pwd)
    logging.info("Password has changed")
    enc_entries = get_entries(session, user.id)
    dec_entries = decrypt_entries(enc_entries, new_pwd)
    dec_entries.sort(key=lambda entry: entry["username"])
    for i in range(len(dec_entries)):
        for field in ["username", "password", "extra"]:
            assert dec_entry_in[field] == dec_entries[i][field]


def test_password_strength_scores():
    email = "fake@foo.io"
    dec_entries = [create_fake_entry(i) for i in range(10)]
    dec_entries.append({
        "account": "no password here",
        "username": "foo",
        "password": "-",
        "has_2fa": False
    })
    l = password_strength_scores(email, dec_entries)
    # check that the no-password account is ignored
    assert len(dec_entries) - 1 == len(l)
    for entry, score in zip(dec_entries, l):
        assert entry["account"] == score["account"]


def test_get_services_map(session):
    # insert a thingy
    session.add(Service(name="MyService"))
    session.commit()
    service_map = get_services_map(session)
    assert len(service_map) == 1
    service_map.get("MyService", None) is not None
