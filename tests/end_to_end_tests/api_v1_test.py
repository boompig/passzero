from __future__ import print_function

import binascii
import os
import unittest

import requests
from six import BytesIO
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm.exc import NoResultFound

import api
from passzero import backend as pz_backend
from passzero.my_env import DATABASE_URL

DEFAULT_EMAIL = "sample@fake.com"


def get_db_session():
    engine = create_engine(DATABASE_URL)
    Session = sessionmaker(bind=engine)
    return Session()


def create_active_account(email, password):
    """Create account and return the user object.
    Use this function instead of API because we do email verification in real API
    """
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
        return { "Content-Type": "application/json" }

    def setUp(self):
        # disable certificate warnings for testing
        requests.packages.urllib3.disable_warnings()

    def tearDown(self):
        # delete account with fake email
        email = DEFAULT_EMAIL
        try:
            db_session = get_db_session()
            user = pz_backend.get_account_with_email(db_session, email)
            assert user is not None
            pz_backend.delete_all_entries(db_session, user)
            pz_backend.delete_all_documents(db_session, user)
            pz_backend.delete_all_auth_tokens(db_session, user)
            pz_backend.delete_account(db_session, user)
        except NoResultFound:
            pass

    def _login(self, session, email, password):
        auth_response = api.login(session, email, password)
        assert auth_response is not None
        assert auth_response.status_code == 200

    def _logout(self, session):
        auth_response = api.logout(session)
        self.assertIsNotNone(auth_response)
        self.assertEqual(auth_response.status_code, 200)


    def _signup(self, session, email, password):
        auth_response = api.signup(session, email, password)
        assert auth_response is not None
        response_json = auth_response.json()
        try:
            assert auth_response.status_code == 200
        except AssertionError as e:
            print(response_json)
            raise e


    def _get_csrf_token(self, session):
        """Return CSRF token"""
        csrf_response = api.get_csrf_token(session)
        self.assertIsNotNone(csrf_response)
        self.assertEqual(csrf_response.status_code, 200)
        token = csrf_response.json()
        assert type(token) == unicode
        assert len(token) != 0
        return token

    def _create_entry(self, session, entry, token):
        """Return entry ID"""
        entry_create_response = api.create_entry(session, entry, token)
        self.assertIsNotNone(entry_create_response)
        self.assertEqual(entry_create_response.status_code, 200)
        entry_id = entry_create_response.json()["entry_id"]
        assert type(entry_id) == int
        return entry_id

    def _edit_entry(self, session, entry_id, entry, token):
        """Returns nothing"""
        entry_edit_response = api.edit_entry(session, entry_id, entry, token)
        self.assertIsNotNone(entry_edit_response)
        response_json = entry_edit_response.json()
        try:
            self.assertEqual(entry_edit_response.status_code, 200)
        except AssertionError as e:
            print(response_json)
            raise e

    def _get_entries(self, session):
        """Return list of entries"""
        entry_response = api.get_entries(session)
        self.assertIsNotNone(entry_response)
        self.assertEqual(entry_response.status_code, 200)
        entries = entry_response.json()
        self.assertIsNotNone(entries)
        assert type(entries) == list
        return entries

    def _delete_entry(self, session, entry_id, token):
        """Returns nothing"""
        entry_delete_response = api.delete_entry(session, entry_id, token)
        self.assertIsNotNone(entry_delete_response)
        self.assertEqual(entry_delete_response.status_code, 200)

    def test_login_no_users(self):
        with requests.Session() as session:
            result = api.login(session, "sample@fake.com", "right_pass")
            assert result is not None
            self.assertEqual(result.status_code, 401)

    def test_no_email(self):
        with requests.Session() as session:
            result = api.login(session, "", "right_pass")
            assert result is not None
            assert result.status_code == 400

    def test_no_password(self):
        with requests.Session() as session:
            result = api.login(session, "sample@fake.com", "")
            assert result is not None
            assert result.status_code == 400

    def test_login_inactive(self):
        email = "sample@fake.com"
        password = "right_pass"
        with requests.Session() as session:
            db_session = get_db_session()
            pz_backend.create_inactive_user(db_session, email, password)
            login_result = api.login(session, email, password)
            # only printed on error
            print(login_result.text)
            assert login_result.status_code == 401

    def test_correct_login(self):
        email = DEFAULT_EMAIL
        password = "right_pass"
        # create account
        user, db_session = create_active_account(email, password)
        with requests.Session() as s:
            self._login(s, email, password)
        db_session = get_db_session()
        # only if test fails
        print(db_session)

    def test_get_entries_empty(self):
        email = DEFAULT_EMAIL
        password = "right_pass"
        user, db_session = create_active_account(email, password)
        with requests.Session() as s:
            self._login(s, email, password)
            entries = self._get_entries(s)
            assert entries == []

    def test_create_no_csrf(self):
        email = DEFAULT_EMAIL
        password = "right_pass"
        user, db_session = create_active_account(email, password)
        with requests.Session() as s:
            self._login(s, email, password)
            entry = {
                "account": "fake",
                "username": "entry_username",
                "password": "entry_pass",
            }
            entry_create_response = api.create_entry(s, entry, "")
            self.assertIsNotNone(entry_create_response)
            assert entry_create_response.status_code == 403
            entries = self._get_entries(s)
            assert entries == []
        db_session = get_db_session()
        # only if test fails
        print(db_session)

    def test_create_and_delete_entry(self):
        email = "sample@fake.com"
        password = "right_pass"
        user, db_session = create_active_account(email, password)
        with requests.Session() as s:
            self._login(s, email, password)
            create_token = self._get_csrf_token(s)
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
        #db_session = get_db_session()
        pz_backend.delete_account(db_session, user)

    def test_get_csrf_token(self):
        with requests.Session() as s:
            self._get_csrf_token(s)

    def test_delete_entry(self):
        email = "sample@fake.com"
        password = "right_pass"
        user, db_session = create_active_account(email, password)
        with requests.Session() as s:
            self._login(s, email, password)
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
        email = "sample@fake.com"
        password = "right_pass"
        user, db_session = create_active_account(email, password)
        assert user.email == email
        with requests.Session() as s:
            self._login(s, email, password)
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
            entry_delete_response = api.delete_entry(s, entry_id, "")
            assert entry_delete_response is not None
            assert entry_delete_response.status_code == 403

    def test_delete_nonexistant_entry(self):
        email = "sample@fake.com"
        password = "right_pass"
        user, db_session = create_active_account(email, password)
        assert user.email == email
        with requests.Session() as s:
            self._login(s, email, password)
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
            assert entry_delete_response is not None
            assert entry_delete_response.status_code == 400

    def _check_entries_equal(self, e1, e2):
        entry_fields = ["account", "username", "password", "extra"]
        for field in entry_fields:
            self.assertIn(field, e1)
            self.assertIn(field, e2)
            self.assertEqual(e1[field], e2[field])

    def test_edit_existing_entry(self):
        email = "sample@fake.com"
        password = "right_pass"
        user, db_session = create_active_account(email, password)
        with requests.Session() as s:
            self._login(s, email, password)
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
        email = "sample@fake.com"
        password = "right_pass"
        user, db_session= create_active_account(email, password)
        with requests.Session() as s:
            self._login(s, email, password)
            token = self._get_csrf_token(s)
            # only if test fails
            print(token)
            entries = self._get_entries(s)
            assert len(entries) == 0
            self._logout(s)
            response = api.get_entries(s)
            self.assertEqual(response.status_code, 401)

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
            create_active_account(DEFAULT_EMAIL, "pass")
            api.login(s, DEFAULT_EMAIL, "pass")
            docs_before = api.get_documents(s).json()
            assert docs_before == []

    def test_upload_then_decrypt(self):
        with requests.Session() as s:
            create_active_account(DEFAULT_EMAIL, "pass")
            api.login(s, DEFAULT_EMAIL, "pass")
            upload_doc_token = api.get_csrf_token(s).json()
            docs_before = api.get_documents(s).json()
            assert docs_before == []
            r = api.post_document(s, "test document",
                    { "document": BytesIO(b"hello world\n") },
                upload_doc_token)
            assert r.status_code == 200
            doc_id = r.json()["document_id"]
            assert isinstance(doc_id, int)
            doc = api.get_document(s, doc_id).json()
            assert binascii.a2b_base64(doc["contents"]) == "hello world\n"
            assert doc["name"] == "test document"

    def test_upload_and_get_docs(self):
        with requests.Session() as s:
            create_active_account(DEFAULT_EMAIL, "pass")
            api.login(s, DEFAULT_EMAIL, "pass")
            upload_doc_token = api.get_csrf_token(s).json()
            docs_before = api.get_documents(s).json()
            assert docs_before == []
            r = api.post_document(s, "test document",
                    { "document": BytesIO(b"hello world\n") },
                upload_doc_token)
            assert r.status_code == 200
            docs_after = api.get_documents(s).json()
            assert len(docs_after) == 1
            assert docs_after[0]["name"] == "test document"

    def test_upload_then_delete(self):
        with requests.Session() as s:
            create_active_account(DEFAULT_EMAIL, "pass")
            api.login(s, DEFAULT_EMAIL, "pass")
            docs_before = api.get_documents(s).json()
            assert docs_before == []
            upload_doc_token = api.get_csrf_token(s).json()
            r = api.post_document(s, "test document",
                    { "document": BytesIO(b"hello world\n") },
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
            create_active_account(DEFAULT_EMAIL, "pass")
            api.login(s, DEFAULT_EMAIL, "pass")
            docs_before = api.get_documents(s).json()
            assert docs_before == []
            r = api.get_document(s, 1)
            assert r.status_code == 400


if __name__ == '__main__':
    import sys
    print("Fatal error: run this file with nosetests command instead", file=sys.stderr)
    sys.exit(1)
