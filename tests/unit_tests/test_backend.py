import logging
import os
from typing import Dict  # noqa: F401

import pytest
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import and_
from sqlalchemy.orm.exc import NoResultFound

from passzero import backend
from passzero.app_factory import create_app
from passzero.backend import (create_inactive_user, decrypt_entries,
                              get_entries, get_services_map,
                              insert_link_for_user,
                              password_strength_scores)
from passzero.change_password import change_password
from passzero.config import ENTRY_LIMITS
from passzero.crypto_utils import PasswordHashAlgo
from passzero.models import (AuthToken,
                             EncryptionKeys, Entry, Link, Service, User)
from passzero.models import db as _db
from tests.unit_tests.utils import (assert_decrypted_entries_equal,
                                    assert_decrypted_links_equal,
                                    get_test_decrypted_entry)

DB_FILENAME = "passzero.db"
DEFAULT_EMAIL = u"fake@fake.com"
DEFAULT_PASSWORD = u"fake password"


@pytest.fixture(scope="module")
def app(request) -> Flask:
    """Provide the fixture for the duration of the test, then tear it down"""
    # remove previous database if present
    if os.path.exists(DB_FILENAME):
        os.remove(DB_FILENAME)

    settings_override = {
        "SQLALCHEMY_DATABASE_URI": "sqlite:///%s" % DB_FILENAME
    }

    _app = create_app(__name__, settings_override)
    ctx = _app.app_context()
    ctx.push()

    def teardown():
        ctx.pop()

    request.addfinalizer(teardown)
    return _app


@pytest.fixture(scope="module")
def db(app: Flask, request) -> SQLAlchemy:
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
def session(db: SQLAlchemy, request):
    """Returns a database scoped session"""
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
        session.query(EncryptionKeys).delete()
        session.commit()

        connection.close()
        session.remove()

    request.addfinalizer(teardown)
    return session


def test_create_inactive_user_sha512(session) -> None:
    u1 = backend.create_inactive_user(session, DEFAULT_EMAIL, DEFAULT_PASSWORD,
                                      password_hash_algo=PasswordHashAlgo.SHA512)
    assert u1.id is not None
    u2 = backend.get_account_with_email(session, DEFAULT_EMAIL)
    assert u1.id == u2.id


def test_create_inactive_user_argon2(session) -> None:
    u1 = backend.create_inactive_user(session, DEFAULT_EMAIL, DEFAULT_PASSWORD,
                                      password_hash_algo=PasswordHashAlgo.Argon2)
    assert u1.id is not None
    u2 = backend.get_account_with_email(session, DEFAULT_EMAIL)
    assert u1.id == u2.id


def test_create_inactive_user(session) -> None:
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


def test_delete_account(session) -> None:
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
    backend.delete_account(session, user)
    try:
        u2 = backend.get_account_with_email(session, email)
        # only printed on error
        print(u2)
        assert False
    except NoResultFound:
        assert True


def test_insert_entry_for_user(session):
    """Test the backend method insert_entry_for_user
    Test all aspects of that method"""
    user_key = u"master key"
    user = backend.create_inactive_user(session, DEFAULT_EMAIL, user_key)

    # first test form validation
    for field, max_length in ENTRY_LIMITS.items():
        try:
            dec_entry = {
                "account": "a",
                "username": "b",
                "password": "c",
                "extra": "d"
            }
            dec_entry[field] = "x" * (max_length + 1)
            backend.insert_entry_for_user(session, dec_entry, user.id, user_key)
        except backend.EntryValidationError:
            assert True
        else:
            assert False
    dec_entry_in = get_test_decrypted_entry()
    new_entry = backend.insert_entry_for_user(session, dec_entry_in, user.id, user_key)
    # make sure the entry is inserted
    enc_entries = get_entries(session, 1)
    assert len(enc_entries) == 1
    dec_entries = decrypt_entries(enc_entries, user_key)
    assert len(dec_entries) == 1
    assert_decrypted_entries_equal(dec_entry_in, dec_entries[0])
    enc_keys_db = session.query(EncryptionKeys).filter_by(user_id=user.id).one()
    # this step should always complete
    keys_db = enc_keys_db.decrypt(user_key)
    assert len(keys_db["entry_keys"]) == 1
    assert str(new_entry.id) in keys_db["entry_keys"]
    entry_key = keys_db["entry_keys"][str(new_entry.id)]["key"]
    dec_entry_out_2 = new_entry.decrypt_with_entry_key(entry_key)
    assert_decrypted_entries_equal(dec_entry_in, dec_entry_out_2)


def test_delete_entry(session):
    user_key = u"master key"
    user = backend.create_inactive_user(session, DEFAULT_EMAIL,
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
    enc_entries_before = backend.get_entries(session, user.id)
    assert len(enc_entries_before) == 10
    delete_index = 3
    # delete one of the inserted entries
    backend.delete_entry(session, enc_entries_before[delete_index].id, user.id, user_key)
    enc_entries_after = get_entries(session, user.id)
    # only 1 entry should be deleted
    assert len(enc_entries_after) == 9
    # make sure that entry is also not present in the keys database
    enc_keys_db = session.query(EncryptionKeys).filter_by(user_id=user.id).one()
    keys_db = enc_keys_db.decrypt(user_key)
    assert len(keys_db["entry_keys"]) == 9
    for i, enc_entry in enumerate(enc_entries_before):
        if i == delete_index:
            assert str(enc_entry.id) not in keys_db["entry_keys"]
        else:
            assert str(enc_entry.id) in keys_db["entry_keys"]


def test_delete_pinned_entry(session):
    """Make sure that we can't delete the pinned entry"""
    user_key = u"master key"
    user = backend.create_inactive_user(session, DEFAULT_EMAIL, user_key)
    # must exist
    pinned_entry = session.query(Entry).filter(and_(
        Entry.pinned == True,  # noqa
        Entry.user_id == user.id
    )).one()
    try:
        backend.delete_entry(session, pinned_entry.id, user.id, user_key)
        assert False
    except AssertionError:
        assert True


def test_delete_all_entries(session):
    user_key = u"master key"
    user = backend.create_inactive_user(session, DEFAULT_EMAIL,
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
    enc_entries = backend.get_entries(session, user.id)
    assert len(enc_entries) == 10
    backend.delete_all_entries(session, user, user_key)
    # make sure all entries are deleted
    enc_entries = get_entries(session, user.id)
    assert len(enc_entries) == 0
    # make sure those entries are also not present in the keys database
    enc_keys_db = session.query(EncryptionKeys).filter_by(user_id=user.id).one()
    keys_db = enc_keys_db.decrypt(user_key)
    assert len(keys_db["entry_keys"]) == 0
    # make sure the pinned entry is still there
    pinned_entry = session.query(Entry).filter(and_(
        Entry.pinned == True,  # noqa
        Entry.user_id == user.id
    )).one()
    assert pinned_entry is not None


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
    dec_entry_in = {
        "account": u"test account",
        "username": u"test username",
        "password": u"test password",
        "extra": u"test extra",
        "has_2fa": True,
    }
    entry = backend.insert_entry_for_user(
        session,
        dec_entry_in,
        user.id,
        user_key,
        version=version
    )
    # save this in case it changes
    entry_id = entry.id
    # edit the entry
    dec_entry_in["password"] = u"a new password"
    dec_entry_in["has_2fa"] = False
    dec_entry_in["username"] = u"a new username"
    # edit the entry
    edited_entry = backend.edit_entry(
        session,
        entry_id,
        user_key,
        dec_entry_in,
        entry.user_id
    )
    # make sure the metadata remains the same
    assert edited_entry.version == version
    assert edited_entry.id == entry_id
    assert edited_entry.user_id == user.id
    # make sure entry is actually edited
    dec_entry_out_1 = edited_entry.decrypt(user_key)
    assert_decrypted_entries_equal(dec_entry_out_1, dec_entry_in)
    # now try to decrypt it using the key stored in encryption keys DB
    enc_keys_db = session.query(EncryptionKeys).filter_by(user_id=user.id).one()
    # this step should always complete
    keys_db = enc_keys_db.decrypt(user_key)
    assert len(keys_db["entry_keys"]) == 1
    assert str(edited_entry.id) in keys_db["entry_keys"]
    entry_key = keys_db["entry_keys"][str(edited_entry.id)]["key"]
    dec_entry_out_2 = edited_entry.decrypt_with_entry_key(entry_key)
    assert_decrypted_entries_equal(dec_entry_in, dec_entry_out_2)


# NOTE: v2 and v1 not tested for now
# because encryption of old versions is no longer supported

def test_edit_entry_v3(session):
    __edit_entry(session, version=3)


def test_edit_entry_v4(session):
    __edit_entry(session, version=4)


def test_edit_entry_v5(session):
    __edit_entry(session, version=5)


def test_edit_entry_fail_validation(session):
    """Try to edit an existing entry but modify it in a way that it would fail validation"""
    user_key = u"test master key"
    user = create_inactive_user(session, u"fake@fake.com", user_key)
    dec_entry_in = {
        "account": "test account",
        "username": "test username",
        "password": "test password",
        "extra": "test extra",
        "has_2fa": True,
    }
    entry = backend.insert_entry_for_user(
        session,
        dec_entry_in,
        user.id,
        user_key,
    )
    # save this in case it changes
    entry_id = entry.id
    # edit the entry
    dec_entry_in["password"] = "a new password"
    dec_entry_in["has_2fa"] = False
    dec_entry_in["username"] = "a" * 1000
    # edit the entry
    try:
        backend.edit_entry(
            session,
            entry_id,
            user_key,
            dec_entry_in,
            entry.user_id
        )
    except backend.EntryValidationError:
        assert True
    else:
        assert False


def test_edit_pinned_entry(session):
    """Make sure you can't edit a pinned entry"""
    user_key = u"test master key"
    user = create_inactive_user(session, u"fake@fake.com", user_key)
    pinned_entry = session.query(Entry).filter(and_(
        Entry.pinned == True,  # noqa
        Entry.user_id == user.id
    )).one()
    new_dec_entry = {
        "account": u"test account",
        "username": u"test username",
        "password": u"test password",
        "extra": u"test extra",
        "has_2fa": True,
    }
    try:
        backend.edit_entry(session, pinned_entry.id, user_key, new_dec_entry, user.id)
        assert False
    except AssertionError:
        assert True


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


def test_update_entry_versions_for_user_only_latest(session) -> None:
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


def test_update_entry_versions_for_user_no_entries(session) -> None:
    user = create_inactive_user(session, DEFAULT_PASSWORD, DEFAULT_PASSWORD)
    # should start with no entries
    entries = backend.get_entries(session, user.id)
    assert entries == []
    num_updated = backend.update_entry_versions_for_user(session, user.id, DEFAULT_PASSWORD)
    assert num_updated == 0
    entries = backend.get_entries(session, user.id)
    assert entries == []


def test_get_account_with_email(session) -> None:
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


def test_change_password(session) -> None:
    """
    Technically this function does not belong here since it doesn't really test the backend.
    We are testing the change_password method of change_password module
    """
    old_pwd = u"hello"
    new_pwd = u"world"
    user = create_inactive_user(session, u"fake@fake.com", old_pwd)
    logging.info("Creating fake entries")
    dec_entries_in = {}  # type: Dict[int, dict]
    dec_links_in = {}  # type: Dict[int, dict]
    for i in range(10):
        dec_entry_in = get_test_decrypted_entry(i)
        entry_id = backend.insert_entry_for_user(session, dec_entry_in,
                                                 user.id, old_pwd).id
        assert isinstance(entry_id, int)
        dec_entries_in[entry_id] = dec_entry_in
    for i in range(10):
        dec_link_in = {
            "service_name": f"service {i}",
            "link": f"https://example.com/foo/{i}",
        }
        link_id = backend.insert_link_for_user(session, dec_link_in,
                                               user.id, old_pwd).id
        assert isinstance(link_id, int)
        dec_links_in[link_id] = dec_link_in

    # validate everything works as it's supposed to with the old password
    enc_entries = get_entries(session, user.id)
    logging.info("Decrypting newly created entries")
    dec_entries = decrypt_entries(enc_entries, old_pwd)
    assert len(dec_entries) == 10
    enc_links = backend.get_links(session, user.id)
    assert len(enc_links) == 10
    # validate the decryption using old password does work
    dec_links_out = [link.decrypt(old_pwd).to_json() for link in enc_links]
    assert len(dec_links_out) == 10

    # validate everything works as it's supposed to with the new password
    logging.info("Changing password")
    change_password(session, user.id, old_pwd, new_pwd)
    logging.info("Password has changed")
    enc_entries = get_entries(session, user.id)
    dec_entries = decrypt_entries(enc_entries, new_pwd)
    for dec_entry_out in dec_entries:
        assert_decrypted_entries_equal(dec_entries_in[dec_entry_out["id"]], dec_entry_out)
    enc_links = backend.get_links(session, user.id)
    dec_links_out = [link.decrypt(new_pwd).to_json() for link in enc_links]
    assert len(dec_links_out) == 10
    for dec_link_out in dec_links_out:
        assert_decrypted_links_equal(dec_link_out, dec_links_in[dec_link_out["id"]])

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
