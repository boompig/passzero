from __future__ import print_function

import logging

import mock
import six

from passzero.app_factory import create_app
from passzero.models import ApiToken, User, Entry, AuthToken
from passzero.models import db as _db

from . import api
import pytest



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
def my_app(request):
    _app = create_app(__name__, settings_override={
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
def app(request, db, my_app):

    def teardown():
        # delete API token
        db.session.query(ApiToken).delete()
        # delete entries
        db.session.query(Entry).delete()
        # delete auth token
        db.session.query(AuthToken).delete()
        # delete user
        db.session.query(User).delete()
        db.session.commit()

    request.addfinalizer(teardown)
    return my_app


def create_active_account(client, email: str, password: str):
    assert isinstance(email, six.text_type)
    assert isinstance(password, six.text_type)
    # signup, etc etc
    #TODO for some reason can't mock out send_confirmation_email so mocking this instead
    with mock.patch("passzero.email.send_email") as m1:
        m1.return_value = True
        r = api.signup(client, email, password)
        assert r.status_code == 200
        # get the token from calls
        token = m1.call_args[0][2].split("?")[1].replace("token=", "")
        # activate
        r = api.activate_account(client, token)
        assert r.status_code == 200


def test_login_then_get_token(app):
    with app.test_client() as client:
        create_active_account(client, DEFAULT_EMAIL, DEFAULT_PASSWORD)
        api.login(client,
                DEFAULT_EMAIL, DEFAULT_PASSWORD, check_status=True)
        token = api.get_api_token_with_login(client, check_status=True)
        assert isinstance(token, six.text_type)


def test_login_then_get_token_twice(app):
    """If you get the token twice, make sure it's the same token"""
    with app.test_client() as client:
        create_active_account(client, DEFAULT_EMAIL, DEFAULT_PASSWORD)
        api.login(client,
                DEFAULT_EMAIL, DEFAULT_PASSWORD, check_status=True)
        token = api.get_api_token_with_login(client, check_status=True)
        t2 = api.get_api_token_with_login(client, check_status=True)
        assert token == t2


def test_login_with_token(app):
    with app.test_client() as client:
        create_active_account(client,
            DEFAULT_EMAIL, DEFAULT_PASSWORD)
        token = api.login_with_token(client,
            DEFAULT_EMAIL, DEFAULT_PASSWORD, check_status=True)
        assert isinstance(token, six.text_type)


def test_login_logout(app):
    with app.test_client() as client:
        create_active_account(client,
            DEFAULT_EMAIL, DEFAULT_PASSWORD)
        token = api.login_with_token(client,
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
        r = api.login_with_token(client,
                "wrong email", "wrong password", check_status=False)
        # only printed on error
        print(r.data)
        assert r.status_code == 401

def test_login_invalid_password(app):
    with app.test_client() as client:
        create_active_account(client, DEFAULT_EMAIL, DEFAULT_PASSWORD)
        r = api.login_with_token(client,
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
    with app.test_client() as client:
        rv = api.delete_entry_with_token(client,
                1, "foo", check_status=False)
        # only print on test failure
        print(rv.data)
        assert rv.status_code == INVALID_TOKEN_CODE


def test_create_entry_no_login(app):
    entry = {
        "account": "foo",
        "username": "bar",
        "password": "baz",
        "extra": "foobar",
        "has_2fa": False
    }
    with app.test_client() as client:
        rv = api.create_entry_with_token(
            client,
            entry,
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
        token = api.login_with_token(client,
            DEFAULT_EMAIL, password, check_status=True)
        for i in range(20):
            entry = {
                "account": "foo-%d" % i,
                "username": "bar-%d" % i,
                "password": "baz-%d" % i,
                "extra": "foobar-%d" % i,
                "has_2fa": (i % 2 == 0)
            }
            api.create_entry_with_token(client,
                    entry, password, token, check_status=True)
        entries = api.get_encrypted_entries_with_token(
            client,
            token,
            check_status=True
        )
        assert len(entries) == 20
        api.delete_all_entries_with_token(client,
                token,
                check_status=True)
        entries = api.get_encrypted_entries_with_token(
            client,
            token,
            check_status=True
        )
        assert len(entries) == 0


def test_delete_invalid_entry(app):
    with app.test_client() as client:
        create_active_account(client, DEFAULT_EMAIL, DEFAULT_PASSWORD)
        token = api.login_with_token(client,
            DEFAULT_EMAIL, DEFAULT_PASSWORD, check_status=True)
        rv = api.delete_entry_with_token(client,
                2014, token, check_status=False)
        # only print on test failure
        print(rv.data)
        assert rv.status_code != 200


def test_get_entries_empty(app):
    with app.test_client() as client:
        create_active_account(client, DEFAULT_EMAIL, DEFAULT_PASSWORD)
        token = api.login_with_token(client,
            DEFAULT_EMAIL, DEFAULT_PASSWORD, check_status=True)
        entries = api.get_encrypted_entries_with_token(client,
                token, check_status=True)
        assert entries == []


def test_create_entry(app):
    with app.test_client() as client:
        email = DEFAULT_EMAIL
        password = DEFAULT_PASSWORD
        create_active_account(client, email, password)
        token = api.login_with_token(client, email, password,
                check_status=True)
        entry = {
            "account": "fake",
            "username": "entry_username",
            "password": "entry_pass",
            "extra": "entry_extra",
            "has_2fa": True
        }
        api.create_entry_with_token(client, entry, password, token,
                check_status=True)
        entries = api.get_encrypted_entries_with_token(client, token,
                check_status=True)
        assert len(entries) == 1

def test_create_entry_no_account(app):
    email = DEFAULT_EMAIL
    password = DEFAULT_PASSWORD
    with app.test_client() as client:
        create_active_account(client, email, password)
        token = api.login_with_token(client, email, password)
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
        real_token = api.login_with_token(client, email, password)
        entry = {
            "account": "fake",
            "username": "entry_username",
            "password": "entry_pass",
            "extra": "entry_extra",
        }
        r = api.create_entry_with_token(client, entry,
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
        token = api.login_with_token(client,
            email, password, check_status=True)
        entry = {
            "account": "my entry",
            "username": "entry_username",
            "password": "entry_pass",
            "extra": "entry_extra",
            "has_2fa": False
        }
        r = api.create_entry_with_token(
            client,
            entry=entry,
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
        token = api.login_with_token(client, email, password, check_status=True)
        # make sure we start with 0 entries
        entries = api.get_encrypted_entries_with_token(client, token,
                check_status=True)
        assert len(entries) == 0
        entry = {
            "account": "fake",
            "username": "entry_username",
            "password": "entry_pass",
            "extra": "entry_extra",
            "has_2fa": False
        }
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
        api.delete_entry_with_token(client, entry_id, token, check_status=True)
        entries = api.get_encrypted_entries_with_token(client, token,
                check_status=True)
        assert len(entries) == 0


def test_edit_non_existant_entry(app):
    email = DEFAULT_EMAIL
    password = DEFAULT_PASSWORD
    with app.test_client() as client:
        create_active_account(client, email, password)
        token = api.login_with_token(client, email, password)
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


def test_edit_entry_no_tags(app):
    email = DEFAULT_EMAIL
    password = DEFAULT_PASSWORD
    with app.test_client() as client:
        create_active_account(client,
            email, password)
        token = api.login_with_token(client,
            email, password, check_status=True)
        old_entry = {
            "account": "fake",
            "username": "entry_username",
            "password": "entry_pass",
            "extra": "entry_extra",
            "has_2fa": False,
            "tags": []
        }
        entry_id = api.create_entry_with_token(
            client,
            old_entry,
            password,
            token,
            check_status=True
        )
        print("Created entry")
        new_entry = {
            "account": "new account",
            "username": "new username",
            "password": "new password",
            "extra": "new extra",
            "has_2fa": True,
            "tags": []
        }
        api.edit_entry_with_token(
            client,
            entry_id,
            new_entry,
            password,
            token,
            check_status=True
        )
        entries = api.get_encrypted_entries_with_token(client,
                token, check_status=True)
        assert len(entries) == 1
        assert entries[0]["id"] == entry_id
        entry_prime = api.decrypt_entry_with_token(client,
                entry_id, password, token, check_status=True)
        _assert_entries_equal(new_entry, entry_prime)


def test_edit_entry_with_tags(app):
    email = DEFAULT_EMAIL
    password = DEFAULT_PASSWORD
    with app.test_client() as client:
        create_active_account(client,
            email, password)
        token = api.login_with_token(client,
            email, password, check_status=True)
        old_entry = {
            "account": "fake",
            "username": "entry_username",
            "password": "entry_pass",
            "extra": "entry_extra",
            "has_2fa": False,
            "tags": ["hello", "world"]
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
            "has_2fa": True,
            "tags": ["first tag", "second tag", "third tag"]
        }
        api.edit_entry_with_token(
            client,
            entry_id,
            new_entry,
            password,
            token,
            check_status=True
        )
        entries = api.get_encrypted_entries_with_token(client,
                token, check_status=True)
        assert len(entries) == 1
        assert entries[0]["id"] == entry_id
        entry_prime = api.decrypt_entry_with_token(client,
                entry_id, password, token, check_status=True)
        _assert_entries_equal(new_entry, entry_prime)


def test_edit_entry_bad_password(app):
    email = DEFAULT_EMAIL
    password = DEFAULT_PASSWORD
    with app.test_client() as client:
        create_active_account(client,
            email, password)
        token = api.login_with_token(client,
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
        t1 = api.login_with_token(client,
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
        t2 = api.login_with_token(client, emails[1], passwords[1], check_status=True)
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
        token = api.login_with_token(client,
            email, password, check_status=True)
        entry = {
            "account": "my entry",
            "username": "entry_username",
            "password": "entry_pass",
            "extra": "entry_extra",
            "has_2fa": False
        }
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
        t1 = api.login_with_token(client,
                emails[0], passwords[0], check_status=True)
        entry = {
            "account": "fake",
            "username": "entry_username",
            "password": "entry_pass",
            "extra": "entry_extra",
            "has_2fa": False
        }
        entry_id = api.create_entry_with_token(client,
                entry, passwords[0], t1, check_status=True)
        # make sure user[1] has no entries
        t2 = api.login_with_token(client, emails[1], passwords[1], check_status=True)
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
        t1 = api.login_with_token(client,
                emails[0], passwords[0], check_status=True)
        entry = {
            "account": "fake",
            "username": "entry_username",
            "password": "entry_pass",
            "extra": "entry_extra",
            "has_2fa": False
        }
        entry_id = api.create_entry_with_token(client,
                entry, passwords[0], t1, check_status=True)
        out_entry_1 = api.decrypt_entry_with_token(client,
                entry_id, passwords[0], t1, check_status=True)
        _assert_entries_equal(out_entry_1, entry)
        # make sure user[1] has no entries
        t2 = api.login_with_token(client, emails[1], passwords[1], check_status=True)
        assert t1 != t2
        entries = api.get_encrypted_entries_with_token(client, t2, check_status=True)
        assert entries == []
        # try editing the entry for user[0] as user[1]
        r = api.delete_entry_with_token(client, entry_id, t2, check_status=False)
        assert r.status_code != 200
        # make sure the entry is still there
        out_entry_2 = api.decrypt_entry_with_token(client,
                entry_id, passwords[0], t1, check_status=True)
        _assert_entries_equal(out_entry_2, entry)


def test_get_entries(app):
    with app.test_client() as client:
        entry = {
            "account": "fake",
            "username": "entry_username",
            "password": "entry_pass",
            "extra": "entry_extra",
            "has_2fa": True,
        }
        create_active_account(client,
                DEFAULT_EMAIL, DEFAULT_PASSWORD)
        token = api.login_with_token(client,
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
        token = api.login_with_token(client,
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
        token = api.login_with_token(client,
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

