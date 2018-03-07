from __future__ import print_function

import logging

import mock
import six

from passzero.app_factory import create_app
from passzero.models import ApiToken, User, Entry, AuthToken
from passzero.models import db as _db

from . import api
import pytest



DEFAULT_EMAIL = u"sample@fake.com"
DEFAULT_PASSWORD = u"right_pass"
INVALID_TOKEN_CODE = 403


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


@mock.patch("passzero.email.send_email")
def create_active_account(client, email: str, password: str, m1):
    assert isinstance(email, six.text_type)
    assert isinstance(password, six.text_type)
    # signup, etc etc
    #TODO for some reason can't mock out send_confirmation_email so mocking this instead
    m1.return_value = True
    r = api.signup(client, email, password)
    print(r.data)
    # only printed on error
    assert r.status_code == 200
    # get the token from calls
    token = m1.call_args[0][2].split("?")[1].replace("token=", "")
    # activate
    r = api.activate_account(client, token)
    print(r.data)
    assert r.status_code == 200


def test_login_then_get_token(app):
    with app.test_client() as client:
        create_active_account(client, DEFAULT_EMAIL, DEFAULT_PASSWORD)
        api.login(client,
                DEFAULT_EMAIL, DEFAULT_PASSWORD, check_status=True)
        token = api.get_api_token_with_login(client, check_status=True)
        assert isinstance(token, six.text_type)


def test_login_with_token(app):
    with app.test_client() as client:
        create_active_account(client,
            DEFAULT_EMAIL, DEFAULT_PASSWORD)
        token = api.login_with_token(client,
            DEFAULT_EMAIL, DEFAULT_PASSWORD, check_status=True)
        assert isinstance(token, six.text_type)


def test_login_invalid_account(app):
    with app.test_client() as client:
        create_active_account(client, DEFAULT_EMAIL, DEFAULT_PASSWORD)
        r = api.login_with_token(client,
                DEFAULT_EMAIL, u"wrong password", check_status=False)
        # only printed on error
        print(r.data)
        assert r.status_code == 401


def test_get_entries_no_login(app):
    with app.test_client() as client:
        rv = api.get_encrypted_entries_with_token(
            client,
            u"foo",
            check_status=False
        )
        assert rv.status_code == INVALID_TOKEN_CODE


def test_delete_entry_no_login(app):
    with app.test_client() as client:
        rv = api.delete_entry_with_token(client,
                1, u"foo", check_status=False)
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
            password=u"foo",
            token=u"foo",
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
        entry_ids = []
        for i in range(20):
            entry = {
                "account": "foo-%d" % i,
                "username": "bar-%d" % i,
                "password": "baz-%d" % i,
                "extra": "foobar-%d" % i,
                "has_2fa": (i % 2 == 0)
            }
            entry_id = api.create_entry_with_token(client,
                    entry, password, token, check_status=True)
            entry_ids.append(entry_id)
        entries = api.get_encrypted_entries_with_token(
            client,
            token,
            check_status=True
        )
        assert len(entries) == 20
        for entry_id in entry_ids:
            api.delete_entry_with_token(client,
                    entry_id,
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
                token=u"foo",
                check_status=False)
        assert r.status_code != 200
        entries = api.get_encrypted_entries_with_token(client, real_token)
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
        assertEntriesEqual(entry, out_entry)
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


def test_edit_existing_entry(app):
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
        assertEntriesEqual(new_entry, entry_prime)


def test_edit_not_your_entry(app):
    emails = [u"email1@fake.com", u"email2@fake.com"]
    password = DEFAULT_PASSWORD
    with app.test_client() as client:
        for email in emails:
            create_active_account(client,
                    email, password)
        # create an entry for user[0]
        t1 = api.login_with_token(client,
                emails[0], password, check_status=True)
        old_entry = {
            "account": "fake",
            "username": "entry_username",
            "password": "entry_pass",
            "extra": "entry_extra",
            "has_2fa": False
        }
        entry_id = api.create_entry_with_token(client,
                old_entry, password, t1, check_status=True)
        entries = api.get_encrypted_entries_with_token(client, t1, check_status=True)
        assert len(entries) == 1
        # make sure user[1] has no entries
        t2 = api.login_with_token(client, emails[1], password, check_status=True)
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
        r = api.edit_entry(client, entry_id, new_entry, t2, check_status=False)
        assert r.status_code != 200
        e2 = api.get_encrypted_entries_with_token(client, t2, check_status=True)
        assert e2 == []
        # make sure that the entries for user[0] are unchanged
        actual_entries = api.get_encrypted_entries_with_token(client, t1)
        assert len(actual_entries) == 1
        assert actual_entries[0]["id"] == entry_id
        actual_entry = api.decrypt_entry_with_token(client,
                entry_id, password, t1, check_status=True)
        assertEntriesEqual(actual_entry, old_entry)


def assertEntriesEqual(e1, e2):
    entry_fields = ["account", "username", "password", "extra"]
    for field in entry_fields:
        assert field in e1
        assert field in e2
        assert e1[field] == e2[field]

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
        assertEntriesEqual(dec_entry_out, entry)


def test_get_entries_not_your_entry(app):
    with app.test_client() as client:
        emails = [u"foo1@foo.com", u"foo2@foo.com"]
        passwords = [u"a_password1", u"a_password2"]
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

