import logging
from unittest import mock

import pytest
import six
from flask import Flask

from passzero import app_factory, backend
from passzero.api.link_list import MAX_NUM_DECRYPT
from passzero.models import (ApiToken, AuthToken, EncryptionKeys, Entry, Link,
                             Service, User)
from passzero.models import db as _db
from tests.common import api
from tests.common.api import BadStatusCodeException
from tests.unit_tests.utils import get_test_decrypted_entry

DEFAULT_EMAIL = "sample@fake.com"
DEFAULT_PASSWORD = "right_pass"
INVALID_TOKEN_CODE = 403


def _assert_entries_equal(e1, e2):
    entry_fields = ["account", "username", "password", "extra"]
    for field in entry_fields:
        assert field in e1
        assert field in e2
        assert e1[field] == e2[field]


@pytest.fixture(scope="module")
def my_app(request) -> Flask:
    _app = app_factory.create_app(__name__, settings_override={
        "SQLALCHEMY_DATABASE_URI": "sqlite://",
        "SQLALCHEMY_TRACK_MODIFICATIONS": False,
        "BUILD_ID": "test",
        "WTF_CSRF_ENABLED": False,
        "JSONIFY_PRETTYPRINT_REGULAR": False
    })
    _app.secret_key = "foo"
    logging.basicConfig(level=logging.DEBUG)
    return _app


@pytest.fixture(scope="module")
def db(request, my_app):
    _db.create_all()

    def teardown():
        _db.drop_all()
    request.addfinalizer(teardown)
    return _db


@pytest.fixture(scope="function")
def app(request, db, my_app: Flask) -> Flask:

    def teardown():
        # delete API token
        db.session.query(ApiToken).delete()
        # delete entries
        db.session.query(Entry).delete()
        # delete links
        db.session.query(Link).delete()
        # delete auth token
        db.session.query(AuthToken).delete()
        # delete user
        db.session.query(User).delete()
        # delete services
        db.session.query(Service).delete()
        # delete encryption key database
        db.session.query(EncryptionKeys).delete()
        db.session.commit()

    request.addfinalizer(teardown)
    return my_app


@mock.patch("passzero.email.send_email")
def create_active_account(client, email: str, password: str, m1):
    assert isinstance(email, six.text_type)
    assert isinstance(password, six.text_type)
    # signup, etc etc
    # TODO for some reason can't mock out send_confirmation_email so mocking this instead
    m1.return_value = True
    r = api.signup(client, email, password)
    assert r.status_code == 200
    # get the token from calls
    token = m1.call_args[0][2].split("?")[1].replace("token=", "")
    # activate
    r = api.activate_account(client, token)
    assert r.status_code == 200


@pytest.fixture(scope="function")
def active_user(db):
    """Create a default active user with email=`DEFAULT_EMAIL` and password=`DEFAULT_PASSWORD`"""
    user = backend.create_inactive_user(
        db_session=db.session,
        email=DEFAULT_EMAIL,
        password=DEFAULT_PASSWORD,
    )
    backend.activate_account(db.session, user)
    yield user

    # then delete that user
    db.session.delete(user)
    db.session.commit()


def test_login_with_email_then_get_token(app):
    with app.test_client() as client:
        create_active_account(client, DEFAULT_EMAIL, DEFAULT_PASSWORD)
        api.login_v2(client,
                     DEFAULT_EMAIL, DEFAULT_PASSWORD, check_status=True)
        token = api.get_api_token_with_login(client, check_status=True)
        assert isinstance(token, six.text_type)


def test_login_then_get_token_twice(app):
    """If you get the token twice, make sure it's the same token"""
    with app.test_client() as client:
        create_active_account(client, DEFAULT_EMAIL, DEFAULT_PASSWORD)
        api.login_v2(client,
                     DEFAULT_EMAIL, DEFAULT_PASSWORD, check_status=True)
        token = api.get_api_token_with_login(client, check_status=True)
        t2 = api.get_api_token_with_login(client, check_status=True)
        assert token == t2


def test_login_with_email_with_token_ok(app: Flask, active_user: User):
    assert isinstance(active_user, User)
    with app.test_client() as client:
        token = api.login_with_email_with_token(client,
                                                DEFAULT_EMAIL, DEFAULT_PASSWORD, check_status=True)
        assert isinstance(token, six.text_type)


def test_login_with_email_with_token_invalid_email(app: Flask, active_user: User):
    assert isinstance(active_user, User)
    with app.test_client() as client:
        # emails must have an @ sign
        r = api.login_with_email_with_token(client,
                                            "invalid email", DEFAULT_PASSWORD, check_status=False)
        assert r.status_code == 400


def test_login_with_username_with_token_ok(app: Flask, active_user: User, db):
    with app.test_client() as client:
        # modify the user to give them a username
        active_user.username = "test"
        db.session.commit()

        # login with that username to get a token
        token = api.login_with_username_with_token(client, "test", DEFAULT_PASSWORD, check_status=True)
        assert isinstance(token, str)


def test_login_with_username_with_token_invalid_username(app: Flask, active_user: User, db):
    with app.test_client() as client:
        # modify the user to give them a username
        active_user.username = "test"
        db.session.commit()

        # usernames may not have an @ sign
        r = api.login_with_username_with_token(client, "test@example.com", DEFAULT_PASSWORD, check_status=False)
        assert r.status_code == 400


def test_login_logout(app):
    with app.test_client() as client:
        create_active_account(client,
                              DEFAULT_EMAIL, DEFAULT_PASSWORD)
        token = api.login_with_email_with_token(client,
                                                DEFAULT_EMAIL, DEFAULT_PASSWORD, check_status=True)
        entries = api.get_encrypted_entries_with_token(client, token, check_status=True)
        # really checking if this operation succeeded
        assert len(entries) == 0
        api.delete_token(client, token, check_status=True)
        r = api.get_encrypted_entries_with_token(client, token, check_status=False)
        assert r.status_code != 200


def test_login_invalid_account(app):
    with app.test_client() as client:
        create_active_account(client, DEFAULT_EMAIL, DEFAULT_PASSWORD)
        r = api.login_with_email_with_token(client,
                                            "wrong_email@example.com", "wrong password", check_status=False)
        # only printed on error
        print(r.data)
        assert r.status_code == 401


def test_login_invalid_password(app):
    with app.test_client() as client:
        create_active_account(client, DEFAULT_EMAIL, DEFAULT_PASSWORD)
        r = api.login_with_email_with_token(client,
                                            DEFAULT_EMAIL, "wrong password", check_status=False)
        # only printed on error
        print(r.data)
        assert r.status_code == 401


def test_get_entries_no_login(app):
    with app.test_client() as client:
        rv = api.get_encrypted_entries_with_token(
            client,
            "foo",
            check_status=False
        )
        assert rv.status_code == INVALID_TOKEN_CODE


def test_delete_entry_no_login(app):
    """Verify we can't hit this API with an invalid token"""
    with app.test_client() as client:
        rv = api.delete_entry_with_token(client,
                                         entry_id=1,
                                         password="foo",
                                         token="foo",
                                         check_status=False)
        # only print on test failure
        print(rv.data)
        assert rv.status_code == INVALID_TOKEN_CODE


def test_create_entry_no_login(app):
    dec_entry = get_test_decrypted_entry()
    with app.test_client() as client:
        rv = api.create_entry_with_token(
            client,
            dec_entry,
            password="foo",
            token="foo",
            check_status=False
        )
        # only print on test failure
        print(rv.data)
        assert rv.status_code == INVALID_TOKEN_CODE


def test_delete_all_entries(app):
    with app.test_client() as client:
        password = DEFAULT_PASSWORD
        create_active_account(client, DEFAULT_EMAIL, password)
        token = api.login_with_email_with_token(client,
                                                DEFAULT_EMAIL, password, check_status=True)
        for i in range(20):
            dec_entry = get_test_decrypted_entry()
            api.create_entry_with_token(client,
                                        dec_entry, password, token, check_status=True)
        entries = api.get_encrypted_entries_with_token(
            client,
            token,
            check_status=True
        )
        assert len(entries) == 20
        api.delete_all_entries_with_token(client,
                                          password,
                                          token,
                                          check_status=True)
        entries = api.get_encrypted_entries_with_token(
            client,
            token,
            check_status=True
        )
        assert len(entries) == 0


def test_delete_invalid_entry(app):
    """Verify we can't delete arbitrary entries"""
    with app.test_client() as client:
        create_active_account(client, DEFAULT_EMAIL, DEFAULT_PASSWORD)
        token = api.login_with_email_with_token(client,
                                                DEFAULT_EMAIL, DEFAULT_PASSWORD, check_status=True)
        rv = api.delete_entry_with_token(client,
                                         entry_id=2014,
                                         password=DEFAULT_PASSWORD,
                                         token=token,
                                         check_status=False)
        # only print on test failure
        print(rv.data)
        assert rv.status_code != 200


def test_get_entries_empty(app):
    with app.test_client() as client:
        create_active_account(client, DEFAULT_EMAIL, DEFAULT_PASSWORD)
        token = api.login_with_email_with_token(client,
                                                DEFAULT_EMAIL, DEFAULT_PASSWORD, check_status=True)
        entries = api.get_encrypted_entries_with_token(client,
                                                       token, check_status=True)
        assert entries == []


def test_create_entry(app):
    with app.test_client() as client:
        email = DEFAULT_EMAIL
        password = DEFAULT_PASSWORD
        create_active_account(client, email, password)
        token = api.login_with_email_with_token(client, email, password,
                                                check_status=True)
        dec_entry = get_test_decrypted_entry()
        api.create_entry_with_token(client, dec_entry, password, token,
                                    check_status=True)
        entries = api.get_encrypted_entries_with_token(client, token,
                                                       check_status=True)
        assert len(entries) == 1


def test_create_entry_no_account(app):
    email = DEFAULT_EMAIL
    password = DEFAULT_PASSWORD
    with app.test_client() as client:
        create_active_account(client, email, password)
        token = api.login_with_email_with_token(client, email, password)
        entry = {
            "username": "entry_username",
            "password": "entry_pass",
            "extra": "entry_extra",
        }
        r = api.create_entry_with_token(client, entry, password, token,
                                        check_status=False)
        assert r.status_code != 200
        entries = api.get_encrypted_entries_with_token(client, token,
                                                       check_status=True)
        assert len(entries) == 0


def test_create_entry_bad_token(app):
    email = DEFAULT_EMAIL
    password = DEFAULT_PASSWORD
    with app.test_client() as client:
        create_active_account(client, email, password)
        real_token = api.login_with_email_with_token(client, email, password)
        dec_entry = get_test_decrypted_entry()
        r = api.create_entry_with_token(client, dec_entry,
                                        password=DEFAULT_PASSWORD,
                                        token="foo",
                                        check_status=False)
        assert r.status_code != 200
        entries = api.get_encrypted_entries_with_token(client, real_token)
        assert len(entries) == 0


def test_create_entry_bad_password(app):
    email = DEFAULT_EMAIL
    password = DEFAULT_PASSWORD
    with app.test_client() as client:
        create_active_account(client,
                              email, password)
        token = api.login_with_email_with_token(client,
                                                email, password, check_status=True)
        dec_entry = get_test_decrypted_entry()
        r = api.create_entry_with_token(
            client,
            entry=dec_entry,
            password="bad pass",
            token=token,
            check_status=False
        )
        assert r.status_code != 200
        # make sure the entry hasn't been created
        entries = api.get_encrypted_entries_with_token(client,
                                                       token, check_status=True)
        assert len(entries) == 0


def test_create_and_delete_entry(app):
    email = DEFAULT_EMAIL
    password = DEFAULT_PASSWORD
    with app.test_client() as client:
        create_active_account(client, email, password)
        token = api.login_with_email_with_token(client, email, password, check_status=True)
        # make sure we start with 0 entries
        entries = api.get_encrypted_entries_with_token(client, token,
                                                       check_status=True)
        assert len(entries) == 0
        entry = get_test_decrypted_entry()
        print("creating entry")
        entry_id = api.create_entry_with_token(client, entry, password, token,
                                               check_status=True)
        entries = api.get_encrypted_entries_with_token(client, token,
                                                       check_status=True)
        assert entry_id == entries[0]["id"]
        out_entry = api.decrypt_entry_with_token(client, entry_id,
                                                 password, token, check_status=True)
        _assert_entries_equal(entry, out_entry)
        assert len(entries) == 1
        api.delete_entry_with_token(client, entry_id, DEFAULT_PASSWORD, token, check_status=True)
        entries = api.get_encrypted_entries_with_token(client, token,
                                                       check_status=True)
        assert len(entries) == 0


def test_edit_non_existant_entry(app):
    email = DEFAULT_EMAIL
    password = DEFAULT_PASSWORD
    with app.test_client() as client:
        create_active_account(client, email, password)
        token = api.login_with_email_with_token(client, email, password)
        old_entry = {
            "account": "fake",
            "username": "entry_username",
            "password": "entry_pass",
            "extra": "entry_extra",
            "has_2fa": False
        }
        entry_id = api.create_entry_with_token(client,
                                               old_entry,
                                               password,
                                               token,
                                               check_status=True)
        new_entry = {
            "account": "new account",
            "username": "new username",
            "password": "new password",
            "extra": "new extra",
            "has_2fa": True
        }
        r = api.edit_entry_with_token(client,
                                      entry_id + 1,
                                      new_entry,
                                      password,
                                      token,
                                      check_status=False)
        assert r.status_code != 200


def test_edit_entry(app):
    email = DEFAULT_EMAIL
    password = DEFAULT_PASSWORD
    with app.test_client() as client:
        api_v3 = api.ApiV3(client)
        create_active_account(client,
                              email, password)
        api_v3.login(email, password)
        old_entry = {
            "account": "fake",
            "username": "entry_username",
            "password": "entry_pass",
            "extra": "entry_extra",
            "has_2fa": False
        }
        entry_id = api_v3.create_entry(
            old_entry,
        )
        old_entry_out = api_v3.decrypt_entry(
            entry_id,
        )
        new_entry = {
            "account": "new account",
            "username": "new username",
            "password": "new password",
            "extra": "new extra",
            "has_2fa": True
        }
        api_v3.edit_entry(
            entry_id,
            new_entry,
        )
        entries = api_v3.get_encrypted_entries()
        assert len(entries) == 1
        assert entries[0]["id"] == entry_id
        new_entry_out = api_v3.decrypt_entry(
            entry_id,
        )
        _assert_entries_equal(new_entry, new_entry_out)
        # verify that the last_modified time has changed UP after editing
        assert old_entry_out["last_modified"] < new_entry_out["last_modified"]


def test_edit_entry_bad_password(app):
    email = DEFAULT_EMAIL
    password = DEFAULT_PASSWORD
    with app.test_client() as client:
        create_active_account(client,
                              email, password)
        token = api.login_with_email_with_token(client,
                                                email, password, check_status=True)
        old_entry = {
            "account": "fake",
            "username": "entry_username",
            "password": "entry_pass",
            "extra": "entry_extra",
            "has_2fa": False
        }
        entry_id = api.create_entry_with_token(
            client,
            old_entry,
            password,
            token,
            check_status=True
        )
        new_entry = {
            "account": "new account",
            "username": "new username",
            "password": "new password",
            "extra": "new extra",
            "has_2fa": True
        }
        r = api.edit_entry_with_token(
            client,
            entry_id,
            new_entry,
            password + "2",
            token,
            check_status=False
        )
        assert r.status_code != 200
        # make sure the entry hasn't changed
        entries = api.get_encrypted_entries_with_token(client,
                                                       token, check_status=True)
        assert len(entries) == 1
        assert entries[0]["id"] == entry_id
        entry_prime = api.decrypt_entry_with_token(client,
                                                   entry_id, password, token, check_status=True)
        _assert_entries_equal(old_entry, entry_prime)


def test_edit_not_your_entry(app):
    emails = ["email1@fake.com", "email2@fake.com"]
    passwords = [DEFAULT_PASSWORD, DEFAULT_PASSWORD + "2"]
    with app.test_client() as client:
        for email, password in zip(emails, passwords):
            create_active_account(client,
                                  email, password)
        # create an entry for user[0]
        t1 = api.login_with_email_with_token(client,
                                             emails[0], passwords[0], check_status=True)
        old_entry = {
            "account": "fake",
            "username": "entry_username",
            "password": "entry_pass",
            "extra": "entry_extra",
            "has_2fa": False
        }
        entry_id = api.create_entry_with_token(client,
                                               old_entry, passwords[0], t1, check_status=True)
        entries = api.get_encrypted_entries_with_token(client, t1, check_status=True)
        assert len(entries) == 1
        # make sure user[1] has no entries
        t2 = api.login_with_email_with_token(client, emails[1], passwords[1], check_status=True)
        assert t1 != t2
        entries = api.get_encrypted_entries_with_token(client, t2, check_status=True)
        assert entries == []
        new_entry = {
            "account": "new account",
            "username": "new username",
            "password": "new password",
            "extra": "new extra",
            "has_2fa": True
        }
        # try editing the entry for user[0] as user[1]
        r = api.edit_entry_with_token(client,
                                      entry_id, new_entry, passwords[1], t2, check_status=False)
        assert r.status_code != 200
        e2 = api.get_encrypted_entries_with_token(client, t2, check_status=True)
        assert e2 == []
        # make sure that the entries for user[0] are unchanged
        actual_entries = api.get_encrypted_entries_with_token(client, t1, check_status=True)
        assert len(actual_entries) == 1
        assert actual_entries[0]["id"] == entry_id
        actual_entry = api.decrypt_entry_with_token(client,
                                                    entry_id, passwords[0], t1, check_status=True)
        _assert_entries_equal(actual_entry, old_entry)


def test_decrypt_entry_bad_password(app):
    email = DEFAULT_EMAIL
    password = DEFAULT_PASSWORD
    with app.test_client() as client:
        create_active_account(client,
                              email, password)
        token = api.login_with_email_with_token(client,
                                                email, password, check_status=True)
        entry = get_test_decrypted_entry()
        entry_id = api.create_entry_with_token(
            client,
            entry=entry,
            password=password,
            token=token,
            check_status=True
        )
        r = api.decrypt_entry_with_token(client, entry_id,
                                         password="bad password", token=token, check_status=False)
        assert r.status_code != 200


def test_decrypt_entry_not_your_entry(app):
    """
    Try to decrypt someone else's entry
    """
    emails = ["email1@fake.com", "email2@fake.com"]
    passwords = [DEFAULT_PASSWORD, DEFAULT_PASSWORD + "2"]
    with app.test_client() as client:
        for email, password in zip(emails, passwords):
            create_active_account(client,
                                  email, password)
        # create an entry for user[0]
        t1 = api.login_with_email_with_token(client,
                                             emails[0], passwords[0], check_status=True)
        entry = get_test_decrypted_entry()
        entry_id = api.create_entry_with_token(client,
                                               entry, passwords[0], t1, check_status=True)
        # make sure user[1] has no entries
        t2 = api.login_with_email_with_token(client, emails[1], passwords[1], check_status=True)
        assert t1 != t2
        entries = api.get_encrypted_entries_with_token(client, t2, check_status=True)
        assert entries == []
        # try editing the entry for user[0] as user[1]
        r = api.decrypt_entry_with_token(client, entry_id, passwords[1], t2, check_status=False)
        assert r.status_code != 200


def test_delete_entry_not_your_entry(app):
    """
    Try to delete someone else's entry
    """
    emails = ["email1@fake.com", "email2@fake.com"]
    passwords = [DEFAULT_PASSWORD, DEFAULT_PASSWORD + "2"]
    with app.test_client() as client:
        for email, password in zip(emails, passwords):
            create_active_account(client,
                                  email, password)
        # create an entry for user[0]
        t1 = api.login_with_email_with_token(client,
                                             emails[0], passwords[0], check_status=True)
        entry = get_test_decrypted_entry()
        entry_id = api.create_entry_with_token(client,
                                               entry, passwords[0], t1, check_status=True)
        out_entry_1 = api.decrypt_entry_with_token(client,
                                                   entry_id, passwords[0], t1, check_status=True)
        _assert_entries_equal(out_entry_1, entry)
        # make sure user[1] has no entries
        t2 = api.login_with_email_with_token(client, emails[1], passwords[1], check_status=True)
        assert t1 != t2
        entries = api.get_encrypted_entries_with_token(client, t2, check_status=True)
        assert entries == []
        # try deleting the entry for user[0] as user[1]
        r = api.delete_entry_with_token(client, entry_id, passwords[1], t2, check_status=False)
        assert r.status_code != 200
        # make sure the entry is still there
        out_entry_2 = api.decrypt_entry_with_token(client,
                                                   entry_id, passwords[0], t1, check_status=True)
        _assert_entries_equal(out_entry_2, entry)


def test_delete_entry_incorrect_password(app: Flask, active_user: User):
    assert active_user.email == DEFAULT_EMAIL
    with app.test_client() as client:
        token = api.login_with_email_with_token(client, DEFAULT_EMAIL, DEFAULT_PASSWORD, check_status=True)
        dec_entry = get_test_decrypted_entry()
        entry_id = api.create_entry_with_token(client, dec_entry, DEFAULT_PASSWORD, token, check_status=True)
        entries = api.get_encrypted_entries_with_token(client, token, check_status=True)
        # number of entries should be 1 after creating the entry
        assert len(entries) == 1
        r = api.delete_entry_with_token(client, entry_id, "bad password", token, check_status=False)
        assert r.status_code == 401
        entries_after = api.get_entries(client, check_status=True)
        # number of entries should still be 1
        assert len(entries_after) == 1


def test_get_entries(app):
    with app.test_client() as client:
        entry = get_test_decrypted_entry()
        create_active_account(client,
                              DEFAULT_EMAIL, DEFAULT_PASSWORD)
        token = api.login_with_email_with_token(client,
                                                DEFAULT_EMAIL, DEFAULT_PASSWORD, check_status=True)
        entry_id = api.create_entry_with_token(client,
                                               entry,
                                               password=DEFAULT_PASSWORD,
                                               token=token,
                                               check_status=True)
        entries = api.get_encrypted_entries_with_token(client,
                                                       token, check_status=True)
        assert len(entries) == 1
        for plaintext_field in ["account"]:
            assert entries[0][plaintext_field] == entry[plaintext_field]
        for encrypted_field in ["username", "password", "extra"]:
            if encrypted_field in entries[0]:
                assert entries[0][encrypted_field] != entry[encrypted_field]
        # now decrypt this individual entry
        dec_entry_out = api.decrypt_entry_with_token(client,
                                                     entry_id, DEFAULT_PASSWORD, token, check_status=True)
        _assert_entries_equal(dec_entry_out, entry)
        assert "last_modified" in dec_entry_out


def test_get_entries_not_your_entry(app):
    with app.test_client() as client:
        emails = ["foo1@foo.com", "foo2@foo.com"]
        passwords = ["a_password1", "a_password2"]
        entry = {
            "account": "fake",
            "username": "entry_username",
            "password": "entry_pass",
            "extra": "entry_extra",
            "has_2fa": False
        }
        # create two accounts
        create_active_account(client, emails[0], passwords[0])
        create_active_account(client, emails[1], passwords[1])
        token = api.login_with_email_with_token(client,
                                                emails[0], passwords[0], check_status=True)
        # create entry for account #1
        entry_id = api.create_entry_with_token(
            client,
            entry=entry,
            password=passwords[0],
            token=token,
            check_status=True
        )
        # make sure the entries exist
        entries = api.get_encrypted_entries_with_token(
            client,
            token=token,
            check_status=True
        )
        assert len(entries) == 1
        # get a token for the second account
        token = api.login_with_email_with_token(client,
                                                emails[1], passwords[1], check_status=True)
        # cannot decrypt entry of person #1 with password of person #2
        r = api.decrypt_entry_with_token(
            client,
            entry_id,
            password=passwords[1],
            token=token,
            check_status=False
        )
        print(r.data)
        assert r.status_code != 200


def test_update_entry_versions(app):
    with app.test_client() as client:
        create_active_account(client, DEFAULT_EMAIL, DEFAULT_PASSWORD)
        pzApi = api.ApiV3(client)
        pzApi.login(DEFAULT_EMAIL, DEFAULT_PASSWORD)
        dec_entry = get_test_decrypted_entry()
        entry_id = pzApi.create_entry(dec_entry)
        num_updated = pzApi.update_entry_versions()
        assert num_updated == 0
        entries = pzApi.get_encrypted_entries()
        assert len(entries) == 1
        assert entries[0]["id"] == entry_id


def _assert_links_equal(l1: dict, l2: dict) -> None:
    for key in ["service_name", "link"]:
        assert key in l1
        assert key in l2
        assert l1[key] == l2[key]


def test_get_links_empty(app):
    with app.test_client() as client:
        create_active_account(client, DEFAULT_EMAIL, DEFAULT_PASSWORD)
        api_v3 = api.ApiV3(client)
        api_v3.login(DEFAULT_EMAIL, DEFAULT_PASSWORD)
        links = api_v3.get_encrypted_links()
        assert links == []


def test_create_link(app):
    with app.test_client() as client:
        create_active_account(client, DEFAULT_EMAIL, DEFAULT_PASSWORD)
        api_v3 = api.ApiV3(client)
        api_v3.login(DEFAULT_EMAIL, DEFAULT_PASSWORD)
        input_link = {
            "service_name": "hello",
            "link": "world",
        }
        link_id = api_v3.create_link(input_link)
        assert link_id is not None
        links = api_v3.get_encrypted_links()
        assert len(links) == 1
        assert links[0]["id"] == link_id


def test_decrypt_link(app):
    with app.test_client() as client:
        create_active_account(client, DEFAULT_EMAIL, DEFAULT_PASSWORD)
        api_v3 = api.ApiV3(client)
        api_v3.login(DEFAULT_EMAIL, DEFAULT_PASSWORD)
        input_link = {
            "service_name": "hello",
            "link": "world",
        }
        link_id = api_v3.create_link(input_link)
        assert link_id is not None
        output_link = api_v3.decrypt_link(link_id)
        _assert_links_equal(input_link, output_link)


def test_delete_link(app):
    with app.test_client() as client:
        create_active_account(client, DEFAULT_EMAIL, DEFAULT_PASSWORD)
        api_v3 = api.ApiV3(client)
        api_v3.login(DEFAULT_EMAIL, DEFAULT_PASSWORD)
        input_link = {
            "service_name": "hello",
            "link": "world",
        }
        link_id = api_v3.create_link(input_link)
        assert link_id is not None
        links = api_v3.get_encrypted_links()
        assert len(links) == 1
        api_v3.delete_link(link_id)
        links_after_delete = api_v3.get_encrypted_links()
        assert links_after_delete == []


def test_delete_link_not_your_link(app):
    with app.test_client() as client:
        api_v3 = api.ApiV3(client)

        # create link as user #1
        create_active_account(client, DEFAULT_EMAIL, DEFAULT_PASSWORD)
        api_v3.login(DEFAULT_EMAIL, DEFAULT_PASSWORD)
        link_id = api_v3.create_link({
            "service_name": "hello",
            "link": "world"
        })
        api_v3.logout()

        # try to delete the link as user #2
        create_active_account(client, "user2@fake.com", DEFAULT_PASSWORD)
        api_v3.login("user2@fake.com", DEFAULT_PASSWORD)
        try:
            api_v3.delete_link(link_id)
            assert False, "must raise error"
        except BadStatusCodeException:
            assert True, "status code should be 400 or similar"
        api_v3.logout()

        # user #1 should still have their link
        api_v3.login(DEFAULT_EMAIL, DEFAULT_PASSWORD)
        links = api_v3.get_encrypted_links()
        assert len(links) == 1
        assert links[0]["id"] == link_id


def test_delete_link_invalid_link(app):
    with app.test_client() as client:
        api_v3 = api.ApiV3(client)
        # create link as user #1
        create_active_account(client, DEFAULT_EMAIL, DEFAULT_PASSWORD)
        api_v3.login(DEFAULT_EMAIL, DEFAULT_PASSWORD)
        link_id = api_v3.create_link({
            "service_name": "hello",
            "link": "world"
        })
        # should only have a single link
        links = api_v3.get_encrypted_links()
        assert len(links) == 1
        try:
            api_v3.delete_link(link_id + 1)
            assert False, "must raise error"
        except BadStatusCodeException as e:
            assert e.status_code == 400


def test_edit_link(app):
    with app.test_client() as client:
        create_active_account(client, DEFAULT_EMAIL, DEFAULT_PASSWORD)
        api_v3 = api.ApiV3(client)
        api_v3.login(DEFAULT_EMAIL, DEFAULT_PASSWORD)
        input_link = {
            "service_name": "hello",
            "link": "world",
        }
        # create the link
        link_id = api_v3.create_link(input_link)
        assert link_id is not None
        # edit the link
        edited_link = {
            "service_name": "foobar",
            "link": "mars"
        }
        api_v3.edit_link(link_id, edited_link)
        # get the link back
        edited_link_out = api_v3.decrypt_link(link_id)
        _assert_links_equal(edited_link, edited_link_out)


def test_decrypt_links_no_links(app):
    """decrypt_links should fail gracefully when no IDs are provided"""
    with app.test_client() as client:
        create_active_account(client, DEFAULT_EMAIL, DEFAULT_PASSWORD)
        api_v3 = api.ApiV3(client)
        api_v3.login(DEFAULT_EMAIL, DEFAULT_PASSWORD)
        r = api_v3.decrypt_links([], check_status=False)
        assert r.status_code == 400


def test_decrypt_links_some_not_yours(app):
    """decrypt_links should gracefully handle when some links are not yours"""
    with app.test_client() as client:
        api_v3 = api.ApiV3(client)

        # create 1 link with another account
        create_active_account(client, "foo1@example.com", "foo1")
        api_v3.login("foo1@example.com", "foo1")
        other_link_id = api_v3.create_link({
            "service_name": "hello - foo1",
            "link": "world - foo1",
        })
        api_v3.logout()

        # create link with my own account
        create_active_account(client, DEFAULT_EMAIL, DEFAULT_PASSWORD)
        api_v3.login(DEFAULT_EMAIL, DEFAULT_PASSWORD)
        dec_link_in_mine = {
            "service_name": "hello - mine",
            "link": "world - mine",
        }
        my_link_id = api_v3.create_link(dec_link_in_mine)
        # try to decrypt with my own account
        dec_links_out = api_v3.decrypt_links([other_link_id, my_link_id], check_status=True)
        assert len(dec_links_out) == 1
        _assert_links_equal(dec_links_out[0], dec_link_in_mine)


def test_decrypt_links_too_many(app):
    dec_links_in = [{
        "service_name": f"hello - {i}",
        "link": f"world - {i}"
    } for i in range(MAX_NUM_DECRYPT + 1)]

    with app.test_client() as client:
        create_active_account(client, DEFAULT_EMAIL, DEFAULT_PASSWORD)
        api_v3 = api.ApiV3(client)
        api_v3.login(DEFAULT_EMAIL, DEFAULT_PASSWORD)
        my_link_ids = []
        for dec_link in dec_links_in:
            my_link_ids.append(api_v3.create_link(dec_link))

        r = api_v3.decrypt_links(my_link_ids, check_status=False)
        assert r.status_code == 400


def test_decrypt_links_bad_password(app):
    """Try to decrypt links without the proper password"""
    with app.test_client() as client:
        create_active_account(client, DEFAULT_EMAIL, DEFAULT_PASSWORD)
        api_v3 = api.ApiV3(client)
        api_v3.login(DEFAULT_EMAIL, DEFAULT_PASSWORD)
        dec_link_in = {
            "service_name": "hello",
            "link": "world",
        }
        my_link_id = api_v3.create_link(dec_link_in)
        r = api_v3.decrypt_links([my_link_id], password="bad password", check_status=False)
        assert r.status_code == 401


def test_decrypt_links_max(app):
    dec_links_in = [{
        "service_name": f"hello - {i}",
        "link": f"world - {i}"
    } for i in range(MAX_NUM_DECRYPT)]

    with app.test_client() as client:
        create_active_account(client, DEFAULT_EMAIL, DEFAULT_PASSWORD)
        api_v3 = api.ApiV3(client)
        api_v3.login(DEFAULT_EMAIL, DEFAULT_PASSWORD)
        my_link_ids = []
        for dec_link in dec_links_in:
            my_link_ids.append(api_v3.create_link(dec_link))

        dec_links_out = api_v3.decrypt_links(my_link_ids, check_status=True)
        assert len(dec_links_out) == len(dec_links_in)
        # arrange the output in order of id
        dec_links_out.sort(key=lambda dec_link: dec_link["id"])
        for (dec_link_in, dec_link_out) in zip(dec_links_in, dec_links_out):
            _assert_links_equal(dec_link_in, dec_link_out)


def test_get_services(app):
    with app.test_client() as client:
        api_v3 = api.ApiV3(client)
        service = Service(name="foo", link="bar")
        _db.session.add(service)
        _db.session.commit()
        services = api_v3.get_services()
        assert isinstance(services, list)
        assert len(services) > 0
        assert services[0]["name"] == "foo"
        assert services[0]["link"] == "bar"


def test_get_current_user(app, active_user: User):
    # create user using test fixture
    assert active_user.username is None
    with app.test_client() as client:
        api_v3 = api.ApiV3(client)
        # first try to get info about the current user without logging in
        r = client.get("/api/v3/user/me")
        assert r.status_code == 401
        api_v3.login(DEFAULT_EMAIL, DEFAULT_PASSWORD)
        user_out = api_v3.get_current_user()
        assert user_out["email"] == DEFAULT_EMAIL
        assert "password" not in user_out
        # must have the username attribute but it's not set
        assert user_out["username"] is None


def test_update_current_user_username(app, active_user: User):
    # create primary user using test fixture
    assert active_user.username is None

    with app.test_client() as client:
        # create a secondary user in the usual way
        create_active_account(client, "test@example.com", "second user")

        api_v3 = api.ApiV3(client)

        # first try to patch the current user without logging in
        # need to call patch explicitly because api_v3 passes token in all calls
        r = client.patch("/api/v3/user/me")
        assert r.status_code == 401

        # login as the default user and patch it with a new username
        api_v3.login(DEFAULT_EMAIL, DEFAULT_PASSWORD)

        # these attempts should fail due to parameter validation errors
        # 1) too short
        r = api_v3.patch_current_user({
            "username": "x"
        }, check_status=False)
        assert r.status_code == 400
        # 2) too long
        r = api_v3.patch_current_user({
            "username": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
        }, check_status=False)
        assert r.status_code == 400
        # 3) reserved keyword
        r = api_v3.patch_current_user({
            "username": "admin",
        }, check_status=False)
        assert r.status_code == 400
        # 4) reserved character/email
        r = api_v3.patch_current_user({
            "username": "test@example.com",
        }, check_status=False)
        assert r.status_code == 400

        r = api_v3.patch_current_user({
            "username": "user1"
        }, check_status=False)
        assert r.status_code == 200

        # make sure the username has changed
        user1_out = api_v3.get_current_user()
        assert user1_out["username"] == "user1"

        # logout as user1 and login as user2
        api_v3.logout()
        api_v3.login("test@example.com", "second user")
        user2_out = api_v3.get_current_user()
        assert user2_out["username"] is None

        # patch user2 with the same username as user1
        r = api_v3.patch_current_user({
            "username": "user1"
        }, check_status=False)
        # this should fail
        assert r.status_code == 400
        # username should still be null
        user2_out = api_v3.get_current_user()
        assert user2_out["username"] is None

        # patch user2 with a different username
        r = api_v3.patch_current_user({
            "username": "user2"
        }, check_status=False)
        # this should succeed
        assert r.status_code == 200
        user2_out = api_v3.get_current_user()
        assert user2_out["username"] == "user2"
