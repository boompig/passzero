"""
This file will test whether the templates fetched can be rendered at all
"""

from __future__ import print_function

import logging
import unittest

import flask
import mock

from . import api

# from passzero.api_v1 import api_v1
from passzero.models import db
from server import app

# app.register_blueprint(api_v1, prefix="")
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite://"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

DEFAULT_EMAIL = "sample@fake.com"
DEFAULT_PASSWORD = "right_pass"

class PassZeroTemplateTester(unittest.TestCase):
    def setUp(self):
        logging.basicConfig(level=logging.DEBUG)
        app.testing = True
        self.app = app
        self.test_client = app.test_client()
        db.app = app
        db.init_app(app)
        db.create_all()

    @mock.patch("passzero.email.send_email")
    def _create_active_account(self, ctx, email, password, m1):
        assert isinstance(email, str)
        assert isinstance(password, str)
        # signup, etc etc
        #TODO for some reason can't mock out send_confirmation_email so mocking this instead
        m1.return_value = True
        r = api.signup(ctx, email, password, check_status=True)
        # get the token from calls
        token = m1.call_args[0][2].split("?")[1].replace("token=", "")
        # link = m1.call_args[0][2][m1.call_args[0][2].index("http://"):]
        # activate
        r = api.activate_account(ctx, token)
        print(r.data)
        assert r.status_code == 200
        # r = api.login(self.app, email, password)
        # print(r.data)
        # assert r.status_code == 200


    # ----- check pages that don't require login

    def test_landing_template(self):
        r = self.test_client.get("/", follow_redirects=True)
        # only print on error
        print(r.data)
        assert r.status_code == 200

    def test_login_template(self):
        r = self.test_client.get("/login", follow_redirects=True)
        print(r.data)
        assert r.status_code == 200

    def test_signup_template(self):
        r = self.test_client.get("/signup", follow_redirects=True)
        print(r.data)
        assert r.status_code == 200

    def test_about_template(self):
        r = self.test_client.get("/about", follow_redirects=True)
        assert r.status_code == 200

    def test_version_template(self):
        r = self.test_client.get("/version", follow_redirects=True)
        assert r.status_code == 200

    def test_recover_template(self):
        r = self.test_client.get("/recover", follow_redirects=True)
        assert r.status_code == 200

    # ---- check redirect methods when pre-conditions not met -----

    def test_post_login_no_login(self):
        r = self.test_client.get("/done_login", follow_redirects=True)
        # only print on error
        print(r.data)
        assert r.status_code == 401

    def test_post_delete_no_login(self):
        r = self.test_client.get("/entries/post_delete/foo", follow_redirects=True)
        # only print on error
        print(r.data)
        assert r.status_code == 401

    def test_post_update_no_login(self):
        r = self.test_client.get("/entries/done_edit/foo", follow_redirects=True)
        # only print on error
        print(r.data)
        assert r.status_code == 401

    def test_post_create_no_login(self):
        r = self.test_client.get("/entries/done_new/foo", follow_redirects=True)
        # only print on error
        print(r.data)
        assert r.status_code == 401

    def test_post_export_no_login(self):
        r = self.test_client.get("/advanced/done_export", follow_redirects=True)
        # only print on error
        print(r.data)
        assert r.status_code == 401

    # ------ check API methods when conditions not met ------------

    def test_export_no_login(self):
        r = self.test_client.get("/advanced/export", follow_redirects=True)
        # only print on error
        print(r.data)
        assert r.status_code == 401

    # ------- check pages that require login to make sure they always redirect back to login page

    def test_edit_entry_no_login(self):
        with self.app.test_client() as c:
            response = c.get("/edit/1", follow_redirects=True)
            print(response.data)
            assert flask.request.path == flask.url_for("login")

    def test_new_entry_no_login(self):
        with self.app.test_client() as c:
            response = c.get("/entries/new", follow_redirects=True)
            print(response.data)
            assert flask.request.path == flask.url_for("login")

    def test_view_entries_no_login(self):
        with self.app.test_client() as c:
            response = c.get("/entries", follow_redirects=True)
            print(response.data)
            assert flask.request.path == flask.url_for("login")

    def test_view_docs_no_login(self):
        with self.app.test_client() as c:
            response = c.get("/docs", follow_redirects=True)
            print(response.data)
            assert flask.request.path == flask.url_for("login")

    def test_new_doc_no_login(self):
        with self.app.test_client() as c:
            response = c.get("/docs/new", follow_redirects=True)
            print(response.data)
            assert flask.request.path == flask.url_for("login")

    def test_edit_doc_no_login(self):
        with self.app.test_client() as c:
            response = c.get("/docs/1", follow_redirects=True)
            print(response.data)
            assert flask.request.path == flask.url_for("login")

    def test_done_doc_edit_redirect_no_login(self):
        with self.app.test_client() as c:
            response = c.get("/docs/done_edit/foo_bar_baz", follow_redirects=True)
            print(response.data)
            # just want to make sure this doesn't error out
            assert (response.status_code == 200 or response.status_code == 401)


    def test_password_strength_no_login(self):
        with self.app.test_client() as c:
            response = c.get("/entries/strength", follow_redirects=True)
            print(response.data)
            assert flask.request.path == flask.url_for("login")

    def test_entry_2fa_no_login(self):
        with self.app.test_client() as c:
            response = c.get("/entries/2fa", follow_redirects=True)
            print(response.data)
            assert flask.request.path == flask.url_for("login")

    def test_advanced_no_login(self):
        with self.app.test_client() as c:
            response = c.get("/advanced", follow_redirects=True)
            print(response.data)
            assert flask.request.path == flask.url_for("login")

    def test_profile_no_login(self):
        with self.app.test_client() as c:
            response = c.get("/profile", follow_redirects=True)
            print(response.data)
            assert flask.request.path == flask.url_for("login")

    def test_logout_no_login(self):
        with self.app.test_client() as c:
            response = c.get("/logout", follow_redirects=True)
            print(response.data)
            assert flask.request.path == flask.url_for("login")

    def test_signup_no_signup(self):
        # just make sure everything is OK
        response = self.test_client.get("/done_signup/foo", follow_redirects=True)
        print(response.data)
        assert response.status_code == 200
    
    def test_confirm_signup_no_token(self):
        """
        This method expects a token.
        Check what happens if no token is supplied
        Just make sure we don't error
        """
        response = self.test_client.get("/signup/confirm", follow_redirects=True)
        print(response.data)
        assert response.status_code == 200

    def test_confirm_signup_invalid_token(self):
        """
        This method expects a token.
        Check what happens if the wrong token is supplied
        Just make sure we don't error
        """
        response = self.test_client.get("/signup/confirm?token=foo", follow_redirects=True)
        print(response.data)
        assert response.status_code == 200

    def test_confirm_recover_no_token(self):
        """
        This method expects a token.
        Check what happens if no token is supplied
        Just make sure we don't error
        """
        # just make sure everything is OK
        response = self.test_client.get("/recover/confirm", follow_redirects=True)
        print(response.data)
        assert response.status_code == 200
    
    def test_confirm_recover_invalid_token(self):
        """
        This method expects a token.
        Check what happens if the wrong token is supplied
        Just make sure we don't error
        """
        response = self.test_client.get("/recover/confirm?token=foo", follow_redirects=True)
        print(response.data)
        assert response.status_code == 200

