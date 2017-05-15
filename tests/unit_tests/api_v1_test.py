# from __future__ import print_function

import json
# import os
# import tempfile
import mock
import unittest
import logging

from passzero.models import db
from passzero.api_v1 import api_v1
from flask import Flask

from . import api

app = Flask(__name__)
app.secret_key = 'foo'
app.register_blueprint(api_v1, prefix="")
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite://"
# app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///passzero.db"
# app.config["SQLALCHEMY_DATABASE_URI"] = "postgresql://daniel_kats:daniel_kats@localhost:5432/passzero"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

DEFAULT_EMAIL = "sample@fake.com"


class PassZeroApiTester(unittest.TestCase):
    # @property
    # def entry_fields(self):
        # return ["account", "username", "password", "extra"]

    @property
    def json_header(self):
        return { "Content-Type": "application/json" }

    def json_post(self, url, data={}):
        return self.app.post(url, data=json.dumps(data),
            headers=self.json_header, follow_redirects=True)

    def setUp(self):
        logging.basicConfig(level=logging.DEBUG)
        self.app = app.test_client()
        db.app = app
        db.init_app(app)
        db.create_all()

    def test_get_entries_no_login(self):
        rv = self.app.get("/api/v1/entries", follow_redirects=True)
        assert json.loads(rv.data)["status"] == "error"
        assert rv.status_code == 401

    def test_delete_entry_no_login(self):
        rv = self.app.delete("/api/v1/entries/1", follow_redirects=True)
        # only print on test failure
        print(rv.data)
        assert rv.status_code == 401
        assert json.loads(rv.data)["status"] == "error"

    def test_edit_entry_no_login(self):
        rv = self.json_post("/api/v1/entries/new")
        # only print on test failure
        print(rv.data)
        assert rv.status_code == 401
        assert json.loads(rv.data)["status"] == "error"

    def login(self, email, password):
        data={
            "email": email,
            "password": password
        }
        return self.json_post("/api/v1/login", data)

    def signup(self, email, password):
        data={
            "email": email,
            "password": password,
            "confirm_password": password
        }
        return self.json_post("/api/v1/signup", data)

    def activate_account(self, token):
        return self.json_post("/api/v1/signup/confirm", {"token": token})

    @mock.patch("passzero.mailgun.send_email")
    def test_signup(self, m1):
        #TODO for some reason can't mock out send_confirmation_email so mocking this instead
        m1.return_value = True
        email = DEFAULT_EMAIL
        password = "fake password"
        r = self.signup(email, password)
        print(r.data)
        # only printed on error
        assert r.status_code == 200
        # get the token from calls
        token = m1.call_args[0][2].split("?")[1].replace("token=", "")
        link = m1.call_args[0][2][m1.call_args[0][2].index("http://"):]
        print(link)
        # activate
        r = self.activate_account(token)
        print(r.data)
        assert r.status_code == 200
        r = self.login(email, password)
        print(r.data)
        assert r.status_code == 200

    def test_get_csrf_token(self):
        token = api.get_csrf_token(self.app)
        assert isinstance(token, str) or isinstance(token, unicode)

    def test_login_invalid_account(self):
        r = self.login(DEFAULT_EMAIL, "world")
        # only printed on error
        print(r.data)
        assert r.status_code == 401

    @mock.patch("passzero.mailgun.send_email")
    def _create_active_account(self, email, password, m1):
        # signup, etc etc
        #TODO for some reason can't mock out send_confirmation_email so mocking this instead
        m1.return_value = True
        email = DEFAULT_EMAIL
        password = "fake password"
        r = self.signup(email, password)
        print(r.data)
        # only printed on error
        assert r.status_code == 200
        # get the token from calls
        token = m1.call_args[0][2].split("?")[1].replace("token=", "")
        # link = m1.call_args[0][2][m1.call_args[0][2].index("http://"):]
        # activate
        r = self.activate_account(token)
        print(r.data)
        assert r.status_code == 200
        r = self.login(email, password)
        print(r.data)
        assert r.status_code == 200

    def test_get_entries_empty(self):
        email = DEFAULT_EMAIL
        password = "right_pass"
        self._create_active_account(email, password)
        self.login(email, password)
        entries = api.get_entries(self.app)
        assert entries == []

    def test_create_entry(self):
        email = DEFAULT_EMAIL
        password = "right_pass"
        self._create_active_account(email, password)
        self.login(email, password)
        token = api.get_csrf_token(self.app)
        entry = {
            "account": "fake",
            "username": "entry_username",
            "password": "entry_pass",
            "extra": "entry_extra",
        }
        api.create_entry(self.app, entry, token)
        entries = api.get_entries(self.app)
        assert len(entries) == 1

    def test_create_and_delete_entry(self):
        email = DEFAULT_EMAIL
        password = "right_pass"
        self._create_active_account(email, password)
        self.login(email, password)
        token = api.get_csrf_token(self.app)
        entry = {
            "account": "fake",
            "username": "entry_username",
            "password": "entry_pass",
            "extra": "entry_extra",
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


