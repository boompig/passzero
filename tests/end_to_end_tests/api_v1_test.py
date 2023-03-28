import os
import unittest
from typing import Tuple

import requests
import six
from six import BytesIO
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

    def _signup(self, session: Session, email: str, password: str):
        auth_response = api.user_signup_v1(session, email, password, check_status=False)
        assert auth_response.status_code == 200
        return auth_response

    def _get_csrf_token(self, session: Session) -> str:
        """Return CSRF token"""
        token = api.get_csrf_token(session)
        assert token is not None
        assert isinstance(token, six.text_type)
        assert len(token) != 0
        return token

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

    def test_get_csrf_token(self):
        with requests.Session() as s:
            self._get_csrf_token(s)

    def _check_entries_equal(self, e1, e2):
        entry_fields = ["account", "username", "password", "extra"]
        for field in entry_fields:
            self.assertIn(field, e1)
            self.assertIn(field, e2)
            self.assertEqual(e1[field], e2[field])

    def test_logout(self):
        create_active_account(DEFAULT_EMAIL, DEFAULT_PASSWORD)
        with requests.Session() as s:
            self._login(s, DEFAULT_EMAIL, DEFAULT_PASSWORD)
            api.get_user_preferences_v1(s, check_status=True)
            self._logout(s)
            response = api.get_user_preferences_v1(s, check_status=False)
            assert response.status_code == 401

    """
    These tests require sending emails

    def test_signup(self):
        email = "sample@fake.com"
        password = "right_pass"
        with requests.Session() as s:
            self._signup(s, email, password)

    """

    def test_no_docs(self):
        with requests.Session() as s:
            create_active_account(DEFAULT_EMAIL, DEFAULT_PASSWORD)
            api.login_v1(s, DEFAULT_EMAIL, DEFAULT_PASSWORD)
            docs_before = api.get_documents(s)
            assert docs_before == []

    def test_upload_doc_then_decrypt(self):
        with requests.Session() as s:
            create_active_account(DEFAULT_EMAIL, DEFAULT_PASSWORD)
            api.login_v1(s, DEFAULT_EMAIL, DEFAULT_PASSWORD)
            upload_doc_token = self._get_csrf_token(s)
            docs_before = api.get_documents(s)
            assert docs_before == []
            doc_params = {
                "name": "test document",
                "document": BytesIO(b"hello world\n"),
                "mimetype": "text/plain"
            }
            doc_id = api.post_document(
                s,
                doc_params,
                upload_doc_token,
                check_status=True
            )
            assert isinstance(doc_id, int)
            r = api.get_document(s, doc_id, check_status=True)
            assert isinstance(r, requests.Response)
            assert r.text == "hello world\n"

    def test_upload_and_get_docs(self):
        with requests.Session() as s:
            create_active_account(DEFAULT_EMAIL, DEFAULT_PASSWORD)
            api.login_v1(s, DEFAULT_EMAIL, DEFAULT_PASSWORD, check_status=True)
            upload_doc_token = self._get_csrf_token(s)
            docs_before = api.get_documents(s, check_status=True)
            assert docs_before == []
            doc_params = {
                "name": "test document",
                "document": BytesIO(b"hello world\n"),
                "mimetype": "text/plain"
            }
            api.post_document(
                s,
                doc_params,
                upload_doc_token,
                check_status=True
            )
            docs_after = api.get_documents(s)
            assert len(docs_after) == 1
            assert docs_after[0]["name"] == "test document"

    def test_upload_doc_then_delete(self):
        with requests.Session() as s:
            create_active_account(DEFAULT_EMAIL, DEFAULT_PASSWORD)
            api.login_v1(s, DEFAULT_EMAIL, DEFAULT_PASSWORD, check_status=True)
            docs_before = api.get_documents(s, check_status=True)
            assert docs_before == []
            upload_doc_token = self._get_csrf_token(s)
            doc_params = {
                "name": "test document",
                "document": BytesIO(b"hello world\n"),
                "mimetype": "text/plain"
            }
            doc_id = api.post_document(
                app=s,
                doc_params=doc_params,
                csrf_token=upload_doc_token,
                check_status=True
            )
            delete_token = self._get_csrf_token(s)
            api.delete_document(s, doc_id, delete_token, check_status=True)
            docs_after_delete = api.get_documents(s)
            assert docs_after_delete == []

    def test_no_such_doc(self):
        with requests.Session() as s:
            create_active_account(DEFAULT_EMAIL, DEFAULT_PASSWORD)
            api.login_v1(s, DEFAULT_EMAIL, DEFAULT_PASSWORD)
            docs_before = api.get_documents(s)
            assert docs_before == []
            r = api.get_document(s, 1, check_status=False)
            assert r.status_code == 400

    # def test_upload_doc_then_update(self):
    #     with requests.Session() as s:
    #         create_active_account(DEFAULT_EMAIL, DEFAULT_PASSWORD)
    #         api.login_v1(s, DEFAULT_EMAIL, DEFAULT_PASSWORD, check_status=True)
    #         docs_before = api.get_documents(s, check_status=True)
    #         assert docs_before == []
    #         upload_doc_token = self._get_csrf_token(s)
    #         doc_params = {
    #             "name": "test document",
    #             "document": BytesIO(b"hello world\n"),
    #             "mimetype": "text/plain"
    #         }
    #         doc_id = api.post_document(
    #             app=s,
    #             doc_params=doc_params,
    #             csrf_token=upload_doc_token,
    #             check_status=True
    #         )
    #         update_token = self._get_csrf_token(s)
    #         new_doc_params = {
    #             "name": "new name for document",
    #             "document": BytesIO(b"hello world 2\n"),
    #             "mimetype": "text/plain"
    #         }
    #         api.update_document(s, doc_id, new_doc_params, update_token, check_status=True)
    #         docs_after_update = api.get_documents(s)
    #         assert len(docs_after_update) == 1
