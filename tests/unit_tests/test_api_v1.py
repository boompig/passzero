from __future__ import print_function

import json
import logging
import unittest

from unittest import mock
import six
from six import BytesIO

from passzero.app_factory import create_app
from passzero.models import db

from . import api

DEFAULT_EMAIL = u"sample@fake.com"
DEFAULT_PASSWORD = u"right_pass"


class PassZeroApiTester(unittest.TestCase):
    def _assert_entries_equal(self, e1: dict, e2: dict) -> None:
        entry_fields = ["account", "username", "password", "extra"]
        for field in entry_fields:
            assert field in e1
            assert field in e2
            assert e1[field] == e2[field]

    def setUp(self):
        logging.basicConfig(level=logging.DEBUG)
        _app = create_app(__name__, settings_override={
            "SQLALCHEMY_DATABASE_URI": "sqlite://",
            "SQLALCHEMY_TRACK_MODIFICATIONS": False,
            "BUILD_ID": "test",
            "WTF_CSRF_ENABLED": False,
            "JSONIFY_PRETTYPRINT_REGULAR": False,
            "TESTING": True,
        })
        self.app = _app.test_client()
        with _app.app_context():
            db.app = _app
            db.init_app(_app)
            db.create_all()

    def tearDown(self):
        db.drop_all()

    def test_delete_all_entries(self):
        self._create_active_account(DEFAULT_EMAIL, u"pass")
        api.login(self.app, DEFAULT_EMAIL, u"pass", check_status=True)
        create_entry_token = api.get_csrf_token(self.app)
        entry = {
            "account": "foo",
            "username": "bar",
            "password": "baz",
            "extra": "foobar",
            "has_2fa": False
        }
        api.create_entry(self.app, entry, create_entry_token, check_status=True)
        entries = api.get_entries(self.app)
        assert len(entries) == 1
        delete_entries_token = api.get_csrf_token(self.app)
        assert delete_entries_token != create_entry_token
        api.delete_all_entries(self.app, delete_entries_token, check_status=True)
        entries = api.get_entries(self.app)
        assert len(entries) == 0

    def test_get_entries_no_login(self):
        rv = api.get_entries(self.app, check_status=False)
        assert json.loads(rv.data)["status"] == "error"
        assert rv.status_code == 401

    def test_delete_entry_no_login(self):
        token = api.get_csrf_token(self.app)
        rv = api.delete_entry(self.app, 1, token, check_status=False)
        # only print on test failure
        print(rv.data)
        assert rv.status_code == 401
        assert json.loads(rv.data)["status"] == "error"

    def test_delete_invalid_entry(self):
        self._create_active_account(DEFAULT_EMAIL, DEFAULT_PASSWORD)
        api.login(self.app, DEFAULT_EMAIL, DEFAULT_PASSWORD)
        token = api.get_csrf_token(self.app)
        rv = api.delete_entry(self.app, 2014, token, check_status=False)
        # only print on test failure
        print(rv.data)
        assert rv.status_code != 200
        assert json.loads(rv.data)["status"] == "error"

    def test_create_entry_no_login(self):
        token = api.get_csrf_token(self.app)
        entry = {
            "account": "foo",
            "username": "bar",
            "password": "baz",
            "extra": "foobar",
            "has_2fa": False
        }
        rv = api.create_entry(self.app, entry, token, check_status=False)
        # only print on test failure
        print(rv.data)
        assert rv.status_code == 401
        assert json.loads(rv.data)["status"] == "error"

    def test_delete_user_with_entries(self):
        email = DEFAULT_EMAIL
        password = DEFAULT_PASSWORD
        self._create_active_account(email, password)
        api.login(self.app, email, password)
        token = api.get_csrf_token(self.app)
        entry = {
            "account": "foo",
            "username": "bar",
            "password": "baz",
            "extra": "foobar",
            "has_2fa": False
        }
        api.create_entry(self.app, entry, token)
        entries = api.get_entries(self.app)
        assert len(entries) == 1
        token = api.get_csrf_token(self.app)
        api.delete_user(self.app, password, token)
        r = api.get_entries(self.app, check_status=False)
        # this should fail
        assert r.status_code == 401
        # now try to login
        r = api.login(self.app, email, password, check_status=False)
        assert r.status_code == 401

    def test_delete_user_with_docs(self):
        email = DEFAULT_EMAIL
        password = DEFAULT_PASSWORD
        self._create_active_account(email, password)
        api.login(self.app, email, password)
        token = api.get_csrf_token(self.app)
        doc_params = {
            "name": "test document",
            "document": (BytesIO(b"hello world\n"), "hello_world.txt"),
            "mimetype": "text/plain"
        }
        api.post_document(self.app, doc_params, token, check_status=True)
        docs = api.get_documents(self.app, check_status=True)
        assert len(docs) == 1
        token = api.get_csrf_token(self.app)
        api.delete_user(self.app, password, token, check_status=True)
        # this should fail
        r = api.get_documents(self.app, check_status=False)
        assert r.status_code == 401
        # now try to login
        r = api.login(self.app, email, password, check_status=False)
        assert r.status_code == 401

    def test_delete_user_bad_password(self):
        self._create_active_account(DEFAULT_EMAIL, DEFAULT_PASSWORD)
        api.login(self.app, DEFAULT_EMAIL, DEFAULT_PASSWORD)
        token = api.get_csrf_token(self.app)
        r = api.delete_user(self.app, u"bad password", token, check_status=False)
        assert r.status_code != 200
        # make sure that I can still get back profile information
        # which would be impossible if account was deleted
        prefs = api.get_user_preferences(self.app, check_status=True)
        assert prefs is not None

    # TODO for some reason can't mock out send_confirmation_email so mocking this instead
    @mock.patch("passzero.email.send_email", return_value=True)
    def test_delete_user_with_recovery_token(self, m1):
        email = DEFAULT_EMAIL
        password = DEFAULT_PASSWORD
        self._create_active_account(email, password)
        api.login(self.app, email, password)
        recover_csrf_token = api.get_csrf_token(self.app)
        api.recover_account(self.app, email, recover_csrf_token)
        recovery_token = self._extract_token_from_send_email_call(m1)
        assert recovery_token != ""
        delete_token = api.get_csrf_token(self.app)
        api.delete_user(self.app, password, delete_token, check_status=True)
        # now we want to use that token to complete account recovery
        confirm_csrf_token = api.get_csrf_token(self.app)
        r = api.recover_account_confirm(self.app, "new password", recovery_token, confirm_csrf_token,
                                        check_status=False)
        print(r.data)
        assert r.status_code != 200

    def _extract_token_from_send_email_call(self, m1):
        token = m1.call_args[0][2].split("?")[1].replace("token=", "")
        return token

    # TODO for some reason can't mock out send_confirmation_email so mocking this instead
    @mock.patch("passzero.email.send_email", return_value=True)
    def test_signup(self, m1):
        email = DEFAULT_EMAIL
        password = u"fake password"
        r = api.signup(self.app, email, password)
        print(r.data)
        # only printed on error
        assert r.status_code == 200
        # get the token from calls
        token = self._extract_token_from_send_email_call(m1)
        link = m1.call_args[0][2][m1.call_args[0][2].index("http://"):]
        print(link)
        # activate
        r = api.activate_account(self.app, token)
        print(r.data)
        assert r.status_code == 200
        r = api.login(self.app, email, password)
        print(r.data)
        assert r.status_code == 200

    def test_get_csrf_token(self):
        token = api.get_csrf_token(self.app)
        assert isinstance(token, six.binary_type) or isinstance(token, six.text_type)

    def test_login(self):
        """
        Make sure the login works.
        Most basic test and good way of discovering stupid mistakes
        """
        self._create_active_account(DEFAULT_EMAIL, DEFAULT_PASSWORD)
        r = api.login(self.app, DEFAULT_EMAIL, DEFAULT_PASSWORD, check_status=True)
        # only printed on error
        print(r.data)
        assert r.status_code == 200

    def test_login_invalid_account(self):
        r = api.login(self.app, DEFAULT_EMAIL, u"world", check_status=False)
        # only printed on error
        print(r.data)
        assert r.status_code == 401

    @mock.patch("passzero.email.send_email")
    def _create_active_account(self, email, password, m1):
        assert isinstance(email, six.text_type)
        assert isinstance(password, six.text_type)
        # signup, etc etc
        # TODO for some reason can't mock out send_confirmation_email so mocking this instead
        m1.return_value = True
        r = api.signup(self.app, email, password)
        print(r.data)
        # only printed on error
        assert r.status_code == 200
        # get the token from calls
        token = m1.call_args[0][2].split("?")[1].replace("token=", "")
        assert isinstance(token, six.text_type)
        # link = m1.call_args[0][2][m1.call_args[0][2].index("http://"):]
        # activate
        r = api.activate_account(self.app, token)
        print(r.data)
        assert r.status_code == 200
        # r = api.login(self.app, email, password)
        # print(r.data)
        # assert r.status_code == 200

    def test_get_entries_empty(self):
        email = DEFAULT_EMAIL
        password = DEFAULT_PASSWORD
        self._create_active_account(email, password)
        api.login(self.app, email, password)
        entries = api.get_entries(self.app)
        assert entries == []

    def test_create_entry(self):
        email = DEFAULT_EMAIL
        password = DEFAULT_PASSWORD
        self._create_active_account(email, password)
        api.login(self.app, email, password)
        token = api.get_csrf_token(self.app)
        entry = {
            "account": "fake",
            "username": "entry_username",
            "password": "entry_pass",
            "extra": "entry_extra",
            "has_2fa": True
        }
        api.create_entry(self.app, entry, token)
        entries = api.get_entries(self.app)
        assert len(entries) == 1

    def test_create_entry_no_account(self):
        email = DEFAULT_EMAIL
        password = DEFAULT_PASSWORD
        self._create_active_account(email, password)
        api.login(self.app, email, password)
        token = api.get_csrf_token(self.app)
        entry = {
            "username": "entry_username",
            "password": "entry_pass",
            "extra": "entry_extra",
        }
        r = api.create_entry(self.app, entry, token, check_status=False)
        assert r.status_code != 200
        entries = api.get_entries(self.app)
        assert len(entries) == 0

    def test_create_entry_bad_csrf(self):
        email = DEFAULT_EMAIL
        password = DEFAULT_PASSWORD
        self._create_active_account(email, password)
        api.login(self.app, email, password)
        token = "foo"
        entry = {
            "account": "fake",
            "username": "entry_username",
            "password": "entry_pass",
            "extra": "entry_extra",
        }
        r = api.create_entry(self.app, entry, token, check_status=False)
        assert r.status_code != 200
        # make sure that this is actually caused by CSRF
        assert "csrf" in json.loads(r.data)["msg"].lower()
        entries = api.get_entries(self.app)
        assert len(entries) == 0

    def test_create_and_delete_entry(self):
        email = DEFAULT_EMAIL
        password = DEFAULT_PASSWORD
        self._create_active_account(email, password)
        api.login(self.app, email, password)
        token = api.get_csrf_token(self.app)
        entry = {
            "account": "fake",
            "username": "entry_username",
            "password": "entry_pass",
            "extra": "entry_extra",
            "has_2fa": False
        }
        print("creating entry")
        entry_id = api.create_entry(self.app, entry, token)
        entries = api.get_entries(self.app)
        assert len(entries) == 1
        print("getting new token")
        delete_token = api.get_csrf_token(self.app)
        assert token != delete_token
        api.delete_entry(self.app, entry_id, delete_token)
        entries = api.get_entries(self.app)
        assert len(entries) == 0

    def test_edit_non_existant_entry(self):
        email = DEFAULT_EMAIL
        password = DEFAULT_PASSWORD
        self._create_active_account(email, password)
        api.login(self.app, email, password)
        create_token = api.get_csrf_token(self.app)
        old_entry = {
            "account": "fake",
            "username": "entry_username",
            "password": "entry_pass",
            "extra": "entry_extra",
            "has_2fa": False
        }
        entry_id = api.create_entry(self.app, old_entry, create_token)
        new_entry = {
            "account": "new account",
            "username": "new username",
            "password": "new password",
            "extra": "new extra",
            "has_2fa": True
        }
        edit_token = api.get_csrf_token(self.app)
        r = api.edit_entry(self.app, entry_id + 1, new_entry, edit_token, check_status=False)
        assert r.status_code != 200

    def test_edit_existing_entry(self):
        email = DEFAULT_EMAIL
        password = DEFAULT_PASSWORD
        self._create_active_account(email, password)
        api.login(self.app, email, password)
        create_token = api.get_csrf_token(self.app)
        old_entry = {
            "account": "fake",
            "username": "entry_username",
            "password": "entry_pass",
            "extra": "entry_extra",
            "has_2fa": False
        }
        entry_id = api.create_entry(self.app, old_entry, create_token)
        new_entry = {
            "account": "new account",
            "username": "new username",
            "password": "new password",
            "extra": "new extra",
            "has_2fa": True
        }
        edit_token = api.get_csrf_token(self.app)
        api.edit_entry(self.app, entry_id, new_entry, edit_token)
        entries = api.get_entries(self.app)
        assert len(entries) == 1
        self._assert_entries_equal(new_entry, entries[0])

    def test_edit_not_your_entry(self):
        emails = [u"email1@fake.com", u"email2@fake.com"]
        password = DEFAULT_PASSWORD
        for email in emails:
            self._create_active_account(email, password)
        api.login(self.app, emails[0], password, check_status=True)
        create_token = api.get_csrf_token(self.app)
        old_entry = {
            "account": "fake",
            "username": "entry_username",
            "password": "entry_pass",
            "extra": "entry_extra",
            "has_2fa": False
        }
        entry_id = api.create_entry(self.app, old_entry, create_token, check_status=True)
        api.logout(self.app, check_status=True)
        api.login(self.app, emails[1], password, check_status=True)
        entries = api.get_entries(self.app, check_status=True)
        assert entries == []
        edit_token = api.get_csrf_token(self.app)
        new_entry = {
            "account": "new account",
            "username": "new username",
            "password": "new password",
            "extra": "new extra",
            "has_2fa": True
        }
        r = api.edit_entry(self.app, entry_id, new_entry, edit_token, check_status=False)
        assert r.status_code == 400
        e2 = api.get_entries(self.app, check_status=True)
        assert e2 == []
        api.logout(self.app)
        api.login(self.app, emails[0], password)
        actual_entries = api.get_entries(self.app)
        self._assert_entries_equal(actual_entries[0], old_entry)

    def test_change_master_password(self):
        email = DEFAULT_EMAIL
        password = u"old_password"
        self._create_active_account(email, password)
        api.login(self.app, email, password)
        create_token = api.get_csrf_token(self.app)
        entry = {
            "account": "fake",
            "username": "entry_username",
            "password": "entry_pass",
            "extra": "entry_extra",
        }
        api.create_entry(self.app, entry, create_token)
        token = api.get_csrf_token(self.app)
        assert token != create_token
        r = api.update_user_password(
            self.app,
            csrf_token=token,
            old_password=password,
            new_password=u"a NEW very long and complicated password 7892384*$@*(!@"
        )
        print(r.data)
        entries = api.get_entries(self.app)
        assert len(entries) == 1
        self._assert_entries_equal(entry, entries[0])

    def test_put_user_prefs(self):
        """Check that you can update preferences"""
        email = DEFAULT_EMAIL
        password = u"old_password"
        self._create_active_account(email, password)
        api.login(self.app, email, password)
        create_token = api.get_csrf_token(self.app)
        prefs = {
            "default_random_password_length": 10,
            "default_random_passphrase_length": 10,
        }
        api.put_user_preferences(self.app, prefs, create_token, check_status=True)
        real_prefs = api.get_user_preferences(self.app, check_status=True)
        assert len(real_prefs) >= len(prefs)
        for k in real_prefs:
            assert k in prefs
            assert prefs[k] == real_prefs[k]

    def test_put_user_prefs_single(self):
        """Check that you can update only a single preference"""
        email = DEFAULT_EMAIL
        password = u"old_password"
        self._create_active_account(email, password)
        api.login(self.app, email, password)
        old_prefs = api.get_user_preferences(self.app, check_status=True)
        assert len(old_prefs) > 0
        create_token = api.get_csrf_token(self.app)
        prefs_to_update = {
            "default_random_password_length": 1,
        }
        api.put_user_preferences(self.app, prefs_to_update, create_token, check_status=True)
        new_prefs = api.get_user_preferences(self.app, check_status=True)
        assert len(new_prefs) == len(old_prefs)
        for k in old_prefs:
            if k not in prefs_to_update:
                assert old_prefs[k] == new_prefs[k]
            else:
                assert old_prefs[k] != new_prefs[k]
                assert prefs_to_update[k] == new_prefs[k]

    def test_change_master_password_bad_old_password(self):
        email = DEFAULT_EMAIL
        old_password = u"old_password"
        self._create_active_account(email, old_password)
        api.login(self.app, email, old_password)
        create_token = api.get_csrf_token(self.app)
        entry = {
            "account": "fake",
            "username": "entry_username",
            "password": "entry_pass",
            "extra": "entry_extra",
        }
        api.create_entry(self.app, entry, create_token)
        token = api.get_csrf_token(self.app)
        assert token != create_token
        new_password = u"a NEW very long and complicated password 7892384*$@*(!@"
        r = api.update_user_password(
            self.app,
            csrf_token=token,
            old_password=u"this is not right",
            new_password=new_password,
            check_status=False
        )
        assert r.status_code != 200
        print(r.data)
        entries = api.get_entries(self.app)
        # but this should still work
        assert len(entries) == 1
        self._assert_entries_equal(entry, entries[0])
        # and logging out and logging in again should work
        r = api.login(self.app, email, old_password)
        assert r.status_code == 200
        r = api.login(self.app, email, new_password, check_status=False)
        assert r.status_code != 200

    def test_logout(self):
        email = DEFAULT_EMAIL
        password = u"old_password"
        self._create_active_account(email, password)
        api.login(self.app, email, password)
        api.logout(self.app)
        r = api.get_entries(self.app, check_status=False)
        # should not be able to get entries
        assert r.status_code == 401

    @mock.patch("passzero.email.send_email")
    def test_recover_account_valid_email(self, m1):
        email = DEFAULT_EMAIL
        old_password = u"a_password"
        self._create_active_account(email, old_password)
        api.login(self.app, email, old_password)
        # create an entry
        entry = {
            "account": "fake",
            "username": "entry_username",
            "password": "entry_pass",
            "extra": "entry_extra",
            "has_2fa": False
        }
        csrf_token = api.get_csrf_token(self.app)
        api.create_entry(self.app, entry, csrf_token)
        entries = api.get_entries(self.app)
        assert len(entries) == 1
        # recover the account
        csrf_token = api.get_csrf_token(self.app)
        recover_result = api.recover_account(self.app, email, csrf_token)
        assert recover_result.status_code == 200
        recovery_token = m1.call_args[0][2].split("?")[1].replace("token=", "")
        print("got recovery token from email: %s" % recovery_token)
        csrf_token = api.get_csrf_token(self.app)
        new_password = u"this is my new password"
        r = api.recover_account_confirm(
            self.app,
            recovery_token=recovery_token,
            csrf_token=csrf_token,
            password=new_password
        )
        assert r.status_code == 200
        # check that you can't do anything here, and that no weird errors trigger
        entries = api.get_entries(self.app)
        assert entries == []
        # now test login
        api.logout(self.app)
        # fail to login with old credentials
        r = api.login(self.app, email, old_password, check_status=False)
        print(r.data)
        assert r.status_code == 401
        # login with new credentials
        r = api.login(self.app, email, new_password)
        assert r.status_code == 200
        # make sure all old entries deleted
        entries = api.get_entries(self.app)
        assert len(entries) == 0
