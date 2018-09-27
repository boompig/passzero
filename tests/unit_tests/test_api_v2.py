
from __future__ import print_function

import json
import logging
import unittest

import mock
import six
from flask import Flask

from passzero.api_v1 import api_v1
from passzero.api_v2 import api_v2
from passzero.models import db

from . import api

app = Flask(__name__)
app.secret_key = 'foo'
app.register_blueprint(api_v1, prefix="/api/v1")
app.register_blueprint(api_v2, prefix="/api/v2")
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite://"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

DEFAULT_EMAIL = u"sample@fake.com"
DEFAULT_PASSWORD = u"a_password"


class PassZeroApiTester(unittest.TestCase):
    def assertEntriesEqual(self, e1, e2):
        entry_fields = ["account", "username", "password", "extra"]
        for field in entry_fields:
            assert field in e1
            assert field in e2
            assert e1[field] == e2[field]

    def setUp(self):
        logging.basicConfig(level=logging.DEBUG)
        self.app = app.test_client()
        db.app = app
        db.init_app(app)
        db.create_all()

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
        # activate
        r = api.activate_account(self.app, token)
        print(r.data)
        assert r.status_code == 200

    def test_get_entries(self):
        entry = {
            "account": "fake",
            "username": "entry_username",
            "password": "entry_pass",
            "extra": "entry_extra",
        }
        self._create_active_account(DEFAULT_EMAIL,
                                    DEFAULT_PASSWORD)
        api.login(self.app, DEFAULT_EMAIL, DEFAULT_PASSWORD)
        csrf_token = api.get_csrf_token(self.app)
        entry_id = api.create_entry(self.app,
                                    entry, csrf_token)
        entries = api.get_entries_v2(self.app)
        assert len(entries) == 1
        for plaintext_field in ["account"]:
            assert entries[0][plaintext_field] == entry[plaintext_field]
        for encrypted_field in ["username", "password", "extra"]:
            if encrypted_field in entries[0]:
                assert entries[0][encrypted_field] != entry[encrypted_field]
        # now decrypt this individual entry
        dec_entry_out = api.get_entry_v2(self.app, entry_id)
        self.assertEntriesEqual(dec_entry_out, entry)

    def test_get_entries_not_your_entry(self):
        emails = [u"foo1@foo.com", u"foo2@foo.com"]
        password = u"a_password"
        entry = {
            "account": "fake",
            "username": "entry_username",
            "password": "entry_pass",
            "extra": "entry_extra",
        }
        self._create_active_account(emails[0], password)
        self._create_active_account(emails[1], password)
        api.login(self.app, emails[0], password)
        csrf_token = api.get_csrf_token(self.app)
        entry_id = api.create_entry(self.app, entry, csrf_token)
        entries = api.get_entries_v2(self.app)
        assert len(entries) == 1
        api.logout(self.app)
        api.login(self.app, emails[1], password)
        r = api.get_entry_v2(self.app, entry_id, check_status=False)
        print(r.data)
        assert r.status_code != 200
        assert json.loads(r.data)["status"] == "error"
