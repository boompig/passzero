import logging
import unittest

import six

from passzero import backend
from passzero.app_factory import create_app
from passzero.models import db, User
from tests.common import api

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

    def _extract_token_from_send_email_call(self, m1):
        token = m1.call_args[0][2].split("?")[1].replace("token=", "")
        return token

    def test_get_csrf_token(self):
        token = api.get_csrf_token(self.app)
        assert isinstance(token, six.binary_type) or isinstance(token, six.text_type)

    def test_login(self):
        """
        Make sure the login works.
        Most basic test and good way of discovering stupid mistakes
        """
        self._create_active_account(DEFAULT_EMAIL, DEFAULT_PASSWORD)
        r = api.login_v1(self.app, DEFAULT_EMAIL, DEFAULT_PASSWORD, check_status=True)
        # only printed on error
        print(r.data)
        assert r.status_code == 200

    def test_login_invalid_account(self):
        r = api.login_v1(self.app, DEFAULT_EMAIL, u"world", check_status=False)
        # only printed on error
        print(r.data)
        assert r.status_code == 401

    def _create_active_account(self, email: str, password: str) -> User:
        assert isinstance(email, six.text_type)
        assert isinstance(password, six.text_type)
        user = backend.create_inactive_user(
            db.session,
            email,
            password
        )
        backend.activate_account(db.session, user)
        return user

    def test_logout(self):
        email = DEFAULT_EMAIL
        password = u"old_password"
        self._create_active_account(email, password)
        api.login_v1(self.app, email, password)
        api.logout_v1(self.app)
        # TODO v1 API no longer has enough methods to properly test logout
