"""
This file will test whether the templates fetched can be rendered at all
"""

from __future__ import print_function

import logging
import unittest

import flask
import mock
import os

from passzero.app_factory import create_app
from passzero.models import db

from . import api

DEFAULT_EMAIL = "sample@fake.com"
DEFAULT_PASSWORD = "right_pass"

class PassZeroTemplateTester(unittest.TestCase):
    def setUp(self):
        logging.basicConfig(level=logging.DEBUG)
        app = create_app(__name__, {
            "SQLALCHEMY_DATABASE_URI": "sqlite://",
            "SQLALCHEMY_TRACK_MODIFICATIONS": False
        })

        app.testing = True
        # template folder has to be explicitly specified
        app.template_folder = os.path.realpath(
            os.path.dirname(__file__) + "/../../templates")

        self.app = app
        self.test_client = app.test_client()
        db.create_all()

    @mock.patch("passzero.email.send_email")
    def _create_active_account(self, client, email: str, password: str, m1):
        assert isinstance(email, str)
        assert isinstance(password, str)
        # signup, etc etc
        #TODO for some reason can't mock out send_confirmation_email so mocking this instead
        m1.return_value = True
        api.signup(client, email, password, check_status=True)
        # get the token from calls
        token = m1.call_args[0][2].split("?")[1].replace("token=", "")
        # link = m1.call_args[0][2][m1.call_args[0][2].index("http://"):]
        # activate
        api.activate_account(client, token, check_status=True)
        # login
        api.login(client, email, password, check_status=True)

    def _create_entry(self, client) -> int:
        token = api.get_csrf_token(client)
        entry = {
            "account": "foo",
            "username": "bar",
            "password": "foobar",
            "extra": "some xtra",
            "has_2fa": True
        }
        return api.create_entry(client, entry, token, check_status=True)

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

    def test_post_account_delete_no_login(self):
        r = self.test_client.get("/post_account_delete", follow_redirects=True)
        assert r.status_code == 200

    def test_post_confirm_signup_no_login(self):
        r = self.test_client.get("/signup/post_confirm", follow_redirects=True)
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
            assert flask.request.path == flask.url_for("main_routes.login")

    def test_new_entry_no_login(self):
        with self.app.test_client() as c:
            response = c.get("/entries/new", follow_redirects=True)
            print(response.data)
            assert flask.request.path == flask.url_for("main_routes.login")

    def test_view_entries_no_login(self):
        with self.app.test_client() as c:
            response = c.get("/view", follow_redirects=True)
            print(response.data)
            assert flask.request.path == flask.url_for("main_routes.login")

    def test_password_strength_no_login(self):
        with self.app.test_client() as c:
            response = c.get("/entries/strength", follow_redirects=True)
            print(response.data)
            assert flask.request.path == flask.url_for("main_routes.login")

    def test_entry_2fa_no_login(self):
        with self.app.test_client() as c:
            response = c.get("/entries/2fa", follow_redirects=True)
            print(response.data)
            assert flask.request.path == flask.url_for("main_routes.login")

    def test_advanced_no_login(self):
        with self.app.test_client() as c:
            response = c.get("/advanced", follow_redirects=True)
            print(response.data)
            assert flask.request.path == flask.url_for("main_routes.login")

    def test_profile_no_login(self):
        with self.app.test_client() as c:
            response = c.get("/profile", follow_redirects=True)
            print(response.data)
            assert flask.request.path == flask.url_for("main_routes.login")

    def test_logout_no_login(self):
        with self.app.test_client() as c:
            response = c.get("/logout", follow_redirects=True)
            print(response.data)
            assert flask.request.path == flask.url_for("main_routes.login")

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

    # ---- test pages that do require login - (auth or abort) ------------

    def test_done_login_with_login(self):
        with self.test_client as c:
            self._create_active_account(c, DEFAULT_EMAIL, DEFAULT_PASSWORD)
            response = c.get("/done_login", follow_redirects=True)
            assert response.status_code == 200

    def test_done_edit_with_login(self):
        with self.test_client as c:
            self._create_active_account(c, DEFAULT_EMAIL, DEFAULT_PASSWORD)
            response = c.get("/entries/done_edit/foo", follow_redirects=True)
            assert response.status_code == 200

    def test_done_new_with_login(self):
        with self.test_client as c:
            self._create_active_account(c, DEFAULT_EMAIL, DEFAULT_PASSWORD)
            response = c.get("/entries/done_new/foo", follow_redirects=True)
            assert response.status_code == 200

    def test_done_login_post_delete(self):
        with self.test_client as c:
            self._create_active_account(c, DEFAULT_EMAIL, DEFAULT_PASSWORD)
            response = c.get("/entries/post_delete/foo", follow_redirects=True)
            assert response.status_code == 200

    def test_done_export_with_login(self):
        with self.test_client as c:
            self._create_active_account(c, DEFAULT_EMAIL, DEFAULT_PASSWORD)
            response = c.get("/advanced/done_export", follow_redirects=True)
            assert response.status_code == 200

    # ----- test pages that do require login - ( auth_or_redirect_login ) -------
    def test_root_with_login(self):
        with self.test_client as c:
            self._create_active_account(c, DEFAULT_EMAIL, DEFAULT_PASSWORD)
            response = c.get("/", follow_redirects=True)
            assert response.status_code == 200
            assert flask.request.path == flask.url_for("main_routes.view_entries")

    def test_new_entry_view_with_login(self):
        with self.test_client as c:
            self._create_active_account(c, DEFAULT_EMAIL, DEFAULT_PASSWORD)
            response = c.get("/entries/new", follow_redirects=True)
            assert response.status_code == 200
            assert flask.request.path != flask.url_for("main_routes.login")

    def test_entry_view_with_login(self):
        with self.test_client as c:
            self._create_active_account(c, DEFAULT_EMAIL, DEFAULT_PASSWORD)
            response = c.get("/view", follow_redirects=True)
            assert response.status_code == 200
            assert flask.request.path != flask.url_for("main_routes.login")

    def test_edit_entry_view_with_login_invalid_entry(self):
        with self.test_client as c:
            self._create_active_account(c, DEFAULT_EMAIL, DEFAULT_PASSWORD)
            response = c.get("/edit/1", follow_redirects=True)
            assert response.status_code == 200
            assert flask.request.path != flask.url_for("main_routes.login")

    def test_strength_view_with_login(self):
        with self.test_client as c:
            self._create_active_account(c, DEFAULT_EMAIL, DEFAULT_PASSWORD)
            response = c.get("/entries/strength", follow_redirects=True)
            assert response.status_code == 200
            assert flask.request.path != flask.url_for("main_routes.login")

    def test_2fa_view_with_login_no_entries(self):
        with self.test_client as c:
            self._create_active_account(c, DEFAULT_EMAIL, DEFAULT_PASSWORD)
            response = c.get("/entries/2fa", follow_redirects=True)
            assert response.status_code == 200
            assert flask.request.path != flask.url_for("main_routes.login")

    def test_2fa_view_with_login_and_entries(self):
        with self.test_client as c:
            self._create_active_account(c, DEFAULT_EMAIL, DEFAULT_PASSWORD)
            self._create_entry(c)
            response = c.get("/entries/2fa", follow_redirects=True)
            assert response.status_code == 200
            assert flask.request.path != flask.url_for("main_routes.login")

    def test_advanced_view_with_login(self):
        with self.test_client as c:
            self._create_active_account(c, DEFAULT_EMAIL, DEFAULT_PASSWORD)
            response = c.get("/advanced", follow_redirects=True)
            assert response.status_code == 200
            assert flask.request.path != flask.url_for("main_routes.login")

    def test_profile_view_with_login(self):
        with self.test_client as c:
            self._create_active_account(c, DEFAULT_EMAIL, DEFAULT_PASSWORD)
            response = c.get("/profile", follow_redirects=True)
            assert response.status_code == 200
            assert flask.request.path != flask.url_for("main_routes.login")

    def test_edit_entry_with_login(self):
        with self.test_client as c:
            self._create_active_account(c, DEFAULT_EMAIL, DEFAULT_PASSWORD)
            entry_id = self._create_entry(c)
            response = c.get("/edit/%d" % entry_id, follow_redirects=True)
            assert response.status_code == 200
            assert flask.request.path != flask.url_for("main_routes.login")

    @mock.patch("passzero.email.send_email")
    def test_recover_account_confirm(self, m1):
        m1.return_value = True
        with self.test_client as c:
            self._create_active_account(c, DEFAULT_EMAIL, DEFAULT_PASSWORD)
            csrf_token = api.get_csrf_token(c)
            api.recover_account(c, DEFAULT_EMAIL, csrf_token)
            # NOTE for whatever reason cannot patch send_recovery_email...
            recovery_token = m1.call_args[0][2].split("token=")[1]
            response = c.get("/recover/confirm?token=%s" % recovery_token,
                follow_redirects=True)
            assert response.status_code == 200
            assert flask.request.path == flask.url_for("main_routes.recover_account_confirm")

    @mock.patch("passzero.email.send_email")
    def test_signup_confirm(self, m1):
        m1.return_value = True
        with self.test_client as c:
            api.signup(c, DEFAULT_EMAIL, DEFAULT_PASSWORD, check_status=True)
            # NOTE for whatever reason cannot patch send_recovery_email...
            recovery_token = m1.call_args[0][2].split("token=")[1]
            response = c.get("/signup/confirm?token=%s" % recovery_token,
                follow_redirects=True)
            assert response.status_code == 200

    # ----------- other login stuff -----------
    def test_logout_with_login(self):
        with self.app.test_client() as c:
            self._create_active_account(c, DEFAULT_EMAIL, DEFAULT_PASSWORD)
            response = c.get("/logout", follow_redirects=True)
            assert response.status_code == 200

