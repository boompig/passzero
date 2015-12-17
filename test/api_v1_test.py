import json
import unittest
import requests
import passzero
from sqlalchemy.orm.exc import NoResultFound
import base64
import logging
from Crypto import Random
from Crypto.Protocol import KDF
from Crypto.Cipher import AES

import api


def json_post(url, data):
    data_json = json.dumps(data)
    headers = { "Content-Type": "application/json" }
    return requests.post(url, data_json, verify=False,
        headers=headers)


def create_active_account(email, password):
    """Create account and return the user object"""
    user = passzero.create_inactive_account(email, password)
    passzero.activate_account(user)
    return user


class PassZeroApi(object):
    """Test version 1 of the JSON API. Use some internal methods
    to create accounts and also to clean up after each testcase.
    Currently uses local psql database."""
    @staticmethod
    def login(session, username, password):
        data = {
            "email": email,
            "password": password
        }
        auth_response = s.post(self.base_url + "/api/login",
            data=json.dumps(data), headers=self.json_header,
            verify=False)
        self.assertIsNotNone(auth_response)
        self.assertEqual(auth_response.status_code, 200)


class PassZeroApiTester(unittest.TestCase):
    @property
    def base_url(self):
        return "https://127.0.0.1:5050"

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
        email = "sample@fake.com"
        try:
            user = passzero.get_account_with_email(email)
            self.assertIsNotNone(user)
            passzero.delete_all_entries(user)
            passzero.delete_all_auth_tokens(user)
            passzero.delete_account(user)
        except NoResultFound:
            pass

    def _login(self, session, email, password):
        auth_response = api.login(session, email, password)
        self.assertIsNotNone(auth_response)
        self.assertEqual(auth_response.status_code, 200)

    def _logout(self, session):
        auth_response = api.logout(session)
        self.assertIsNotNone(auth_response)
        self.assertEqual(auth_response.status_code, 200)


    def _signup(self, session, email, password):
        auth_response = api.signup(session, email, password)
        self.assertIsNotNone(auth_response)
        response_json = auth_response.json()
        try:
            self.assertEqual(auth_response.status_code, 200)
        except AssertionError as e:
            print response_json
            raise e


    def _get_csrf_token(self, session):
        """s is session. Return CSRF token"""
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
            print response_json
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

    def test_correct_login(self):
        email = "sample@fake.com"
        password = "right_pass"
        # create account
        user =create_active_account(email, password)
        with requests.Session() as s:
            self._login(s, email, password)
        passzero.delete_account(user)

    def test_get_entries_empty(self):
        email = "sample@fake.com"
        password = "right_pass"
        user = create_active_account(email, password)
        with requests.Session() as s:
            self._login(s, email, password)
            entries = self._get_entries(s)
            assert entries == []
        passzero.delete_account(user)

    def test_create_no_csrf(self):
        email = "sample@fake.com"
        password = "right_pass"
        user = create_active_account(email, password)
        with requests.Session() as s:
            self._login(s, email, password)
            entry = {
                "account": "fake",
                "username": "entry_username",
                "password": "entry_pass",
            }
            entry_create_response = s.post(self.base_url + "/api/entries/new",
                data=json.dumps(entry),
                headers=self.json_header, verify=False)
            self.assertIsNotNone(entry_create_response)
            assert entry_create_response.status_code == 403

            entries = self._get_entries(s)
            assert entries == []
        passzero.delete_account(user)

    def test_create_and_delete_entry(self):
        email = "sample@fake.com"
        password = "right_pass"
        user = create_active_account(email, password)
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
            entries = self._get_entries(s)
            assert len(entries) == 1
            self._delete_entry(s, entry_id, token)
            entries = self._get_entries(s)
            assert len(entries) == 0
        passzero.delete_account(user)

    def test_get_csrf_token(self):
        with requests.Session() as s:
            self._get_csrf_token(s)

    def test_delete_entry(self):
        email = "sample@fake.com"
        password = "right_pass"
        user = create_active_account(email, password)
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
            self._delete_entry(s, entry_id, token)
            entries = self._get_entries(s)
            assert entries == []

    def test_delete_entry_no_token(self):
        email = "sample@fake.com"
        password = "right_pass"
        user = create_active_account(email, password)
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
            url = self.base_url + "/api/entries/{}".format(
                entry_id)
            entry_delete_response = s.delete(url,
                headers=self.json_header, verify=False)
            assert entry_delete_response is not None
            assert entry_delete_response.status_code == 403

    def test_delete_nonexistant_entry(self):
        email = "sample@fake.com"
        password = "right_pass"
        user = create_active_account(email, password)
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
            url = self.base_url + "/api/entries/{}?csrf_token={}".format(
                entry_id + 1, token)
            entry_delete_response = s.delete(url,
                headers=self.json_header, verify=False)
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
        user = create_active_account(email, password)
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
            entry["account"] = "new account"
            entry["username"] = "new_username"
            entry["password"] = "new_password"
            entry["extra"] = "new extra"
            self._edit_entry(s, entry_id, entry, token)
            entries = self._get_entries(s)
            assert len(entries) == 1
            self._check_entries_equal(entry, entries[0])


    def test_logout(self):
        email = "sample@fake.com"
        password = "right_pass"
        user = create_active_account(email, password)
        with requests.Session() as s:
            self._login(s, email, password)
            token = self._get_csrf_token(s)
            entries = self._get_entries(s)
            assert len(entries) == 0
            self._logout(s)
            response = api.get_entries(s)
            self.assertEqual(response.status_code, 401)


    def test_signup(self):
        email = "sample@fake.com"
        password = "right_pass"
        with requests.Session() as s:
            self._signup(s, email, password)


if __name__ == '__main__':
    import sys
    print >>sys.stderr, "Run with nosetests"
    sys.exit(1)
