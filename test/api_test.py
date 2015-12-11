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

#from crypto_utils import *

"""
Very hacky API testing - runs on local server
"""


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
            # delete all encrypted entries
            passzero.delete_all_encrypted_entries(user)
            passzero.delete_account(user)
        except NoResultFound:
            pass

    def _login(self, s, email, password):
        """s is session"""
        data={
            "email": email,
            "password": password
        }
        auth_response = s.post(self.base_url + "/api/login",
            data=json.dumps(data), headers=self.json_header,
            verify=False)
        self.assertIsNotNone(auth_response)
        self.assertEqual(auth_response.status_code, 200)

    def _get_csrf_token(self, s):
        """s is session. Return CSRF token"""
        csrf_response = s.get(self.base_url + "/api/csrf_token",
            headers=self.json_header, verify=False)
        assert csrf_response is not None
        assert csrf_response.status_code == 200
        token = csrf_response.json()
        assert type(token) == unicode
        assert len(token) != 0
        return token

    def _create_entry(self, s, entry):
        """s is session. Return entry ID."""
        entry_create_response = s.post(self.base_url + "/api/entries/new",
            data=json.dumps(entry),
            headers=self.json_header, verify=False)
        self.assertIsNotNone(entry_create_response)
        self.assertEqual(entry_create_response.status_code, 200)
        entry_id = entry_create_response.json()["entry_id"]
        assert type(entry_id) == int
        return entry_id

    def _get_entries(self, s):
        entry_response = s.get(self.base_url + "/api/entries",
            headers=self.json_header, verify=False)
        assert entry_response is not None
        assert entry_response.status_code == 200
        entries = entry_response.json()
        assert entries is not None
        assert type(entries) == list
        return entries

    def _delete_entry(self, s, entry_id, token):
        url = self.base_url + "/api/entries/{}?csrf_token={}".format(
            entry_id, token)
        entry_delete_response = s.delete(url,
            headers=self.json_header, verify=False)
        assert entry_delete_response is not None
        assert entry_delete_response.status_code == 200

    def test_wrong_login(self):
        result = json_post(
            url=self.base_url + "/api/login",
            data={
                "email": "sample@fake.com",
                "password": "wrong_pass"
            }
        )
        assert result is not None
        assert result.status_code == 401

    def test_no_email(self):
        result = json_post(
            url=self.base_url + "/api/login",
            data={
                "password": "wrong_pass"
            }
        )
        assert result is not None
        assert result.status_code == 400

    def test_no_password(self):
        result = json_post(
            url=self.base_url + "/api/login",
            data={
                "password": "wrong_pass"
            }
        )
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
                "csrf_token": token
            }
            entry_id = self._create_entry(s, entry)
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
                "csrf_token": token
            }
            entry_id = self._create_entry(s, entry)
            self._delete_entry(s, entry_id, token)
            entries = self._get_entries(s)
            assert entries == []
        passzero.delete_account(user)

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
                "csrf_token": token
            }
            entry_id = self._create_entry(s, entry)
            url = self.base_url + "/api/entries/{}".format(
                entry_id)
            entry_delete_response = s.delete(url,
                headers=self.json_header, verify=False)
            assert entry_delete_response is not None
            assert entry_delete_response.status_code == 403
        passzero.delete_account(user)

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
                "csrf_token": token
            }
            entry_id = self._create_entry(s, entry)
            url = self.base_url + "/api/entries/{}?csrf_token={}".format(
                entry_id + 1, token)
            entry_delete_response = s.delete(url,
                headers=self.json_header, verify=False)
            assert entry_delete_response is not None
            assert entry_delete_response.status_code == 400
        passzero.delete_account(user)

    def _create_cse(self, session, entry):
        data_json = json.dumps(entry)
        response = session.post(self.base_url + "/api/v2/entries",
            data=data_json, headers=self.json_header, verify=False)
        self.assertIsNotNone(response)
        self.assertEqual(response.status_code, 200)
        entry_id = response.json()["entry_id"]
        self.assertIsNotNone(entry_id)
        assert type(entry_id) == int
        return entry_id

    def _get_cse(self, session):
        """Given session, return list of encrypted entries."""
        response = session.get(self.base_url + "/api/v2/entries",
            headers=self.json_header, verify=False)
        assert response is not None
        assert response.status_code == 200
        enc_entries = response.json()
        assert type(enc_entries) == list
        return enc_entries

    def _decrypt_field(self, extended_key, ciphertext, iv):
        cipher = AES.new(extended_key, AES.MODE_CFB, iv)
        return cipher.decrypt(ciphertext)

    def _encrypt_field(self, extended_key, msg, iv):
        cipher = AES.new(extended_key, AES.MODE_CFB, iv)
        return cipher.encrypt(msg)

    def _get_key_salt(self):
        return Random.new().read(32)

    def _get_iv(self):
        return Random.new().read(AES.block_size)

    def _delete_cse(self, session, entry_id, token):
        url = self.base_url + "/api/v2/entries/{}?csrf_token={}".format(
            entry_id, token)
        response = session.delete(url,
            headers=self.json_header, verify=False)
        self.assertIsNotNone(response)
        self.assertEqual(response.status_code, 200)
        return response.json()

    def _decrypt_cse(self, key, enc_entry):
        self.assertIn("key_salt", enc_entry)
        raw_salt = base64.b64decode(enc_entry["key_salt"])
        extended_key = KDF.PBKDF2(key, raw_salt)
        self.assertIn("iv", enc_entry)
        raw_iv = base64.b64decode(enc_entry["iv"])
        dec_entry = {}
        for field in self.entry_fields:
            self.assertIn(field, enc_entry)
            raw_field = base64.b64decode(enc_entry[field])
            dec_entry[field] = self._decrypt_field(extended_key,
                raw_field, raw_iv)
            logging.debug(field)
            logging.debug(enc_entry[field])
            logging.debug(dec_entry[field])
        return dec_entry

    def _check_entries_equal(self, e1, e2):
        for field in self.entry_fields:
            logging.debug("Checking field %s" % field)
            self.assertIn(field, e1)
            self.assertIn(field, e2)
            self.assertEqual(e1[field], e2[field])

    def _encrypt_cse(self, key, entry):
        key_salt = self._get_key_salt()
        extended_key = KDF.PBKDF2(key, key_salt)
        iv = self._get_iv()
        enc_entry = {}
        for field in self.entry_fields:
            ciphertext = self._encrypt_field(extended_key,
                entry[field], iv)
            enc_entry[field] = base64.b64encode(ciphertext)
            logging.debug(field)
            logging.debug(enc_entry[field])
        enc_entry["iv"] = base64.b64encode(iv)
        enc_entry["key_salt"] = base64.b64encode(key_salt)
        enc_entry["csrf_token"] = entry["csrf_token"]
        return enc_entry

    def test_cse_create_and_delete(self):
        email = "sample@fake.com"
        password = "right_pass"
        user = create_active_account(email, password)
        with requests.Session() as s:
            self._login(s, email, password)
            enc_entries = self._get_cse(s)
            assert enc_entries == []
            token = self._get_csrf_token(s)
            entry = {
                "account": "fake_account",
                "username": "entry_username",
                "password": "entry_pass",
                "extra": "",
                "csrf_token": token
            }
            enc_entry = self._encrypt_cse(password, entry)
            entry_id = self._create_cse(s, enc_entry)
            enc_entries = self._get_cse(s)
            self.assertEqual(len(enc_entries), 1)
            self._check_entries_equal(enc_entry, enc_entries[0])
            dec_entry = self._decrypt_cse(password, enc_entries[0])
            logging.debug("checking entries equal...")
            self._check_entries_equal(entry, dec_entry)
            logging.debug("deleting...")
            self._delete_cse(s, entry_id, token)
        passzero.delete_account(user)

    def test_get_cse_empty(self):
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
                "extra": "",
                "csrf_token": token
            }
            enc_entries = self._get_cse(s)
            assert enc_entries == []
        passzero.delete_account(user)


if __name__ == '__main__':
    import sys
    print >>sys.stderr, "Run with nosetests"
    sys.exit(1)
