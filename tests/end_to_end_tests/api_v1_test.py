import os
import unittest
from typing import Tuple

import requests
import six
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm.exc import NoResultFound
from sqlalchemy.orm.session import Session

from passzero import backend as pz_backend
from passzero.models.user import User
from passzero.my_env import DATABASE_URL
from tests.common import api

DEFAULT_EMAIL = u"sample@fake.com"
DEFAULT_PASSWORD = u"right_pass"


def get_db_session() -> Session:
    engine = create_engine(DATABASE_URL)
    session_factory = sessionmaker(bind=engine)
    return session_factory()


def create_active_account(email: str, password: str) -> Tuple[User, Session]:
    """Create account and return the user object.
    Use this function instead of API because we do email verification in real API
    """
    assert isinstance(email, six.text_type)
    assert isinstance(password, six.text_type)
    db_session = get_db_session()
    try:
        pz_backend.get_account_with_email(db_session, email)
        raise Exception("User with email %s already exists" % email)
    except NoResultFound:
        pass
    user = pz_backend.create_inactive_user(db_session, email, password)
    pz_backend.activate_account(db_session, user)
    return user, db_session


class PassZeroApiV1Tester(unittest.TestCase):
    @property
    def base_url(self):
        assert 'LIVE_TEST_HOST' in os.environ, \
            "Did not find 'LIVE_TEST_HOST' among environment variables"
        return os.environ['LIVE_TEST_HOST']

    @property
    def entry_fields(self):
        return ["account", "username", "password", "extra"]

    @property
    def json_header(self):
        return {"Content-Type": "application/json"}

    def _fake_account_cleanup(self):
        # delete account with fake email
        try:
            db_session = get_db_session()
            user = pz_backend.get_account_with_email(db_session, DEFAULT_EMAIL)
            assert user is not None
            pz_backend.delete_account(db_session, user)
        except NoResultFound:
            pass

    def setUp(self):
        # delete the account if it exists
        self._fake_account_cleanup()

    def tearDown(self):
        self._fake_account_cleanup()

    def _login(self, session: Session, email: str, password: str):
        auth_response = api.login_v1(session, email, password, check_status=True)
        assert auth_response is not None
        assert auth_response.status_code == 200

    def _logout(self, session: Session):
        api.logout_v1(session, check_status=True)

    def test_login_no_users(self):
        with requests.Session() as session:
            response = api.login_v1(session, DEFAULT_EMAIL, DEFAULT_PASSWORD, check_status=False)
            print(response.text)
            assert response is not None
            assert response.status_code == 401

    def test_no_email(self):
        with requests.Session() as session:
            response = api.login_v1(session, u"", DEFAULT_PASSWORD, check_status=False)
            print(response.text)
            assert response is not None
            assert response.status_code == 400

    def test_no_password(self):
        with requests.Session() as session:
            response = api.login_v1(session, DEFAULT_EMAIL, u"", check_status=False)
            print(response.text)
            assert response is not None
            assert response.status_code == 400

    def test_login_inactive(self):
        with requests.Session() as session:
            db_session = get_db_session()
            pz_backend.create_inactive_user(db_session, DEFAULT_EMAIL, DEFAULT_PASSWORD)
            login_response = api.login_v1(session, DEFAULT_EMAIL, DEFAULT_PASSWORD, check_status=False)
            # only printed on error
            print(login_response.text)
            assert login_response.status_code == 401

    def test_correct_login(self):
        # create account
        _, db_session = create_active_account(DEFAULT_EMAIL, DEFAULT_PASSWORD)
        with requests.Session() as s:
            self._login(s, DEFAULT_EMAIL, DEFAULT_PASSWORD)
        db_session = get_db_session()
        # only if test fails
        print(db_session)

    def test_logout(self):
        # TODO we no longer have enough v1 functions to test logout
        create_active_account(DEFAULT_EMAIL, DEFAULT_PASSWORD)
        with requests.Session() as s:
            self._login(s, DEFAULT_EMAIL, DEFAULT_PASSWORD)
            self._logout(s)
