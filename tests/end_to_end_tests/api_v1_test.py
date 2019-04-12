from __future__ import print_function

import base64
import os
import unittest

import requests
import six
from six import BytesIO
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm.exc import NoResultFound
from sqlalchemy.orm.session import Session
from typing import Tuple, List

from passzero import backend as pz_backend
from passzero.models.user import User
from passzero.my_env import DATABASE_URL

from . import api

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
        # disable certificate warnings for testing
        requests.packages.urllib3.disable_warnings()
        # delete the account if it exists
        self._fake_account_cleanup()

    def tearDown(self):
        self._fake_account_cleanup()

    def _login(self, session: Session, email: str, password: str):
        auth_response = api.login(session, email, password)
        assert auth_response is not None
        assert auth_response.status_code == 200

    def _logout(self, session: Session):
        auth_response = api.logout(session)
        self.assertIsNotNone(auth_response)
        auth_response.status_code == 200

    def _signup(self, session: Session, email: str, password: str):
        auth_response = api.signup(session, email, password)
        assert auth_response is not None
        response_json = auth_response.json()
        try:
            assert auth_response.status_code == 200
        except AssertionError as e:
            print(response_json)
            raise e

    def _get_csrf_token(self, session: Session) -> str:
        """Return CSRF token"""
        csrf_response = api.get_csrf_token(session)
        self.assertIsNotNone(csrf_response)
        self.assertEqual(csrf_response.status_code, 200)
        token = csrf_response.json()
        assert isinstance(token, six.text_type)
        assert len(token) != 0
        return token

    def _create_entry(self, session: Session, entry: dict, token: str) -> int:
        """Return entry ID"""
        entry_create_response = api.create_entry(session, entry, token)
        print(entry_create_response.text)
        assert entry_create_response is not None
        entry_create_response.status_code == 200
        entry_id = entry_create_response.json()["entry_id"]
        assert isinstance(entry_id, int)
        return entry_id

    def _edit_entry(self, session: Session, entry_id: int, entry: dict, token: str):
        """Returns nothing"""
        entry_edit_response = api.edit_entry(session, entry_id, entry, token)
        assert entry_edit_response is not None
        response_json = entry_edit_response.json()
        try:
            assert entry_edit_response.status_code == 200
        except AssertionError as e:
            print(response_json)
            raise e

    def _get_entries(self, session: Session) -> List[dict]:
        """Return list of entries"""
        entry_response = api.get_entries(session)
        assert entry_response is not None
        assert entry_response.status_code == 200
        entries = entry_response.json()
        self.assertIsNotNone(entries)
        assert isinstance(entries, list)
        return entries

    def _delete_entry(self, session: Session, entry_id: int, token: str):
        """Returns nothing"""
        entry_delete_response = api.delete_entry(session, entry_id, token)
        self.assertIsNotNone(entry_delete_response)
        self.assertEqual(entry_delete_response.status_code, 200)

    def test_login_no_users(self):
        with requests.Session() as session:
            result = api.login(session, DEFAULT_EMAIL, DEFAULT_PASSWORD)
            print(result)
            assert result is not None
            self.assertEqual(result.status_code, 401)

    def test_no_email(self):
        with requests.Session() as session:
            result = api.login(session, u"", DEFAULT_PASSWORD)
            print(result)
            assert result is not None
            assert result.status_code == 400

    def test_no_password(self):
        with requests.Session() as session:
            result = api.login(session, DEFAULT_EMAIL, u"")
            print(result.text)
            assert result is not None
            assert result.status_code == 400

    def test_login_inactive(self):
        with requests.Session() as session:
            db_session = get_db_session()
            pz_backend.create_inactive_user(db_session, DEFAULT_EMAIL, DEFAULT_PASSWORD)
            login_result = api.login(session, DEFAULT_EMAIL, DEFAULT_PASSWORD)
            # only printed on error
            print(login_result.text)
            assert login_result.status_code == 401

    def test_correct_login(self):
        # create account
        user, db_session = create_active_account(DEFAULT_EMAIL, DEFAULT_PASSWORD)
        with requests.Session() as s:
            self._login(s, DEFAULT_EMAIL, DEFAULT_PASSWORD)
        db_session = get_db_session()
        # only if test fails
        print(db_session)

    def test_get_entries_empty(self):
        user, db_session = create_active_account(DEFAULT_EMAIL, DEFAULT_PASSWORD)
        with requests.Session() as s:
            self._login(s, DEFAULT_EMAIL, DEFAULT_PASSWORD)
            entries = self._get_entries(s)
            assert entries == []

    def test_create_no_csrf(self):
        user, db_session = create_active_account(DEFAULT_EMAIL, DEFAULT_PASSWORD)
        with requests.Session() as s:
            self._login(s, DEFAULT_EMAIL, DEFAULT_PASSWORD)
            entry = {
                "account": "fake",
                "username": "entry_username",
                "password": "entry_pass",
            }
            entry_create_response = api.create_entry(s, entry, u"")
            self.assertIsNotNone(entry_create_response)
            assert entry_create_response.status_code == 403
            entries = self._get_entries(s)
            assert entries == []
        db_session = get_db_session()
        # only if test fails
        print(db_session)

    def test_create_and_delete_entry(self):
        user, db_session = create_active_account(DEFAULT_EMAIL, DEFAULT_PASSWORD)
        with requests.Session() as s:
            self._login(s, DEFAULT_EMAIL, DEFAULT_PASSWORD)
            create_token = self._get_csrf_token(s)
            assert isinstance(create_token, six.text_type)
            entry = {
                "account": "fake",
                "username": "entry_username",
                "password": "entry_pass",
                "extra": "entry_extra",
            }
            entry_id = self._create_entry(s, entry, create_token)
            entries = self._get_entries(s)
            assert len(entries) == 1
            delete_token = self._get_csrf_token(s)
            assert delete_token != create_token
            self._delete_entry(s, entry_id, delete_token)
            entries = self._get_entries(s)
            assert len(entries) == 0
        pz_backend.delete_account(db_session, user)

    def test_get_csrf_token(self):
        with requests.Session() as s:
            self._get_csrf_token(s)

    def test_delete_entry(self):
        user, db_session = create_active_account(DEFAULT_EMAIL, DEFAULT_PASSWORD)
        with requests.Session() as s:
            self._login(s, DEFAULT_EMAIL, DEFAULT_PASSWORD)
            create_token = self._get_csrf_token(s)
            entry = {
                "account": "fake",
                "username": "entry_username",
                "password": "entry_pass",
                "extra": "entry_extra",
            }
            entry_id = self._create_entry(s, entry, create_token)
            delete_token = self._get_csrf_token(s)
            self._delete_entry(s, entry_id, delete_token)
            entries = self._get_entries(s)
            assert entries == []

    def test_delete_entry_no_token(self):
        user, db_session = create_active_account(DEFAULT_EMAIL, DEFAULT_PASSWORD)
        assert user.email == DEFAULT_EMAIL
        with requests.Session() as s:
            self._login(s, DEFAULT_EMAIL, DEFAULT_PASSWORD)
            token = self._get_csrf_token(s)
            entry = {
                "account": "fake",
                "username": "entry_username",
                "password": "entry_pass",
                "extra": "entry_extra",
            }
            entry_id = self._create_entry(s, entry, token)
            # only printed on error
            print(entry_id)
            entries = self._get_entries(s)
            assert len(entries) == 1
            entry_delete_response = api.delete_entry(s, entry_id, u"")
            assert entry_delete_response is not None
            assert entry_delete_response.status_code == 403

    def test_delete_nonexistant_entry(self):
        user, db_session = create_active_account(DEFAULT_EMAIL, DEFAULT_PASSWORD)
        assert user.email == DEFAULT_EMAIL
        with requests.Session() as s:
            self._login(s, DEFAULT_EMAIL, DEFAULT_PASSWORD)
            create_token = self._get_csrf_token(s)
            entry = {
                "account": "fake",
                "username": "entry_username",
                "password": "entry_pass",
                "extra": "entry_extra",
            }
            entry_id = self._create_entry(s, entry, create_token)
            delete_token = self._get_csrf_token(s)
            entry_delete_response = api.delete_entry(s, entry_id + 100, delete_token)
            print(entry_delete_response.text)
            assert entry_delete_response is not None
            assert entry_delete_response.status_code == 400

    def _check_entries_equal(self, e1, e2):
        entry_fields = ["account", "username", "password", "extra"]
        for field in entry_fields:
            self.assertIn(field, e1)
            self.assertIn(field, e2)
            self.assertEqual(e1[field], e2[field])

    def test_edit_existing_entry(self):
        user, db_session = create_active_account(DEFAULT_EMAIL, DEFAULT_PASSWORD)
        with requests.Session() as s:
            self._login(s, DEFAULT_EMAIL, DEFAULT_PASSWORD)
            create_token = self._get_csrf_token(s)
            entry = {
                "account": "fake",
                "username": "entry_username",
                "password": "entry_pass",
                "extra": "entry_extra",
            }
            entry_id = self._create_entry(s, entry, create_token)
            entry["account"] = "new account"
            entry["username"] = "new_username"
            entry["password"] = "new_password"
            entry["extra"] = "new extra"
            edit_token = self._get_csrf_token(s)
            self._edit_entry(s, entry_id, entry, edit_token)
            entries = self._get_entries(s)
            assert len(entries) == 1
            self._check_entries_equal(entry, entries[0])

    def test_logout(self):
        user, db_session = create_active_account(DEFAULT_EMAIL, DEFAULT_PASSWORD)
        with requests.Session() as s:
            self._login(s, DEFAULT_EMAIL, DEFAULT_PASSWORD)
            token = self._get_csrf_token(s)
            # only if test fails
            print(token)
            entries = self._get_entries(s)
            assert len(entries) == 0
            self._logout(s)
            response = api.get_entries(s)
            assert response.status_code == 401

    """
    These tests require sending emails

    def test_signup(self):
        email = "sample@fake.com"
        password = "right_pass"
        with requests.Session() as s:
            self._signup(s, email, password)

    def test_recover_account_invalid_email(self):
        email = "sample@fake.com"
        with requests.Session() as s:
            token = self._get_csrf_token(s)
            recover_result = api.recover(s, email, token)
            # not actually printed unless there is failure
            print(recover_result)
            self.assertEqual(recover_result.status_code, 401)

    def test_recover_account_valid_email(self):
        email = "sample@fake.com"
        password = "a_password"
        user, db_session = create_active_account(email, password)
        with requests.Session() as s:
            token = self._get_csrf_token(s)
            recover_result = api.recover(s, email, token)
            # not actually printed unless there is failure
            print(recover_result.text)
            self.assertEqual(recover_result.status_code, 200)


    def test_recover_account_valid_email_inactive(self):
        email = "sample@fake.com"
        password = "a_password"
        with requests.Session() as s:
            self._signup(s, email, password)
            token = self._get_csrf_token(s)
            recover_result = api.recover(s, email, token)
            assert recover_result.status_code == 200
    """

    def test_no_docs(self):
        with requests.Session() as s:
            create_active_account(DEFAULT_EMAIL, DEFAULT_PASSWORD)
            api.login(s, DEFAULT_EMAIL, DEFAULT_PASSWORD)
            docs_before = api.get_documents(s).json()
            assert docs_before == []

    def test_upload_then_decrypt(self):
        with requests.Session() as s:
            create_active_account(DEFAULT_EMAIL, DEFAULT_PASSWORD)
            api.login(s, DEFAULT_EMAIL, DEFAULT_PASSWORD)
            upload_doc_token = api.get_csrf_token(s).json()
            docs_before = api.get_documents(s).json()
            assert docs_before == []
            doc_params = {"document": BytesIO(b"hello world\n")}
            r = api.post_document(s, u"test document", doc_params,
                                  upload_doc_token)
            print(r.status_code)
            print(r.text)
            assert r.status_code == 200
            doc_id = r.json()["document_id"]
            assert isinstance(doc_id, int)
            r = api.get_document(s, doc_id)
            # for debugging
            print(r)
            print(r.text)
            print(r.status_code)
            # doc = api.get_document(s, doc_id).json()
            doc = r.json()
            print(doc)
            assert base64.b64decode(doc["contents"]) == b"hello world\n"
            assert doc["name"] == "test document"

    def test_upload_and_get_docs(self):
        with requests.Session() as s:
            create_active_account(DEFAULT_EMAIL, DEFAULT_PASSWORD)
            api.login(s, DEFAULT_EMAIL, DEFAULT_PASSWORD)
            upload_doc_token = api.get_csrf_token(s).json()
            docs_before = api.get_documents(s).json()
            assert docs_before == []
            doc_params = {"document": BytesIO(b"hello world\n")}
            r = api.post_document(s, u"test document",
                                  doc_params, upload_doc_token)
            assert r.status_code == 200
            docs_after = api.get_documents(s).json()
            assert len(docs_after) == 1
            assert docs_after[0]["name"] == "test document"

    def test_upload_then_delete(self):
        with requests.Session() as s:
            create_active_account(DEFAULT_EMAIL, DEFAULT_PASSWORD)
            api.login(s, DEFAULT_EMAIL, DEFAULT_PASSWORD)
            docs_before = api.get_documents(s).json()
            assert docs_before == []
            upload_doc_token = api.get_csrf_token(s).json()
            doc_params = {"document": BytesIO(b"hello world\n")}
            r = api.post_document(s, u"test document",
                                  doc_params,
                                  upload_doc_token)
            assert r.status_code == 200
            doc_id = r.json()["document_id"]
            delete_token = api.get_csrf_token(s).json()
            r = api.delete_document(s, doc_id, delete_token)
            assert r.status_code == 200
            docs_after_delete = api.get_documents(s).json()
            assert docs_after_delete == []

    def test_no_such_doc(self):
        with requests.Session() as s:
            create_active_account(DEFAULT_EMAIL, DEFAULT_PASSWORD)
            api.login(s, DEFAULT_EMAIL, DEFAULT_PASSWORD)
            docs_before = api.get_documents(s).json()
            assert docs_before == []
            r = api.get_document(s, 1)
            assert r.status_code == 400


if __name__ == '__main__':
    import sys
    print("Fatal error: run this file with nosetests command instead", file=sys.stderr)
    sys.exit(1)
