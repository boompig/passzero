import json
import unittest
import requests
import passzero
from sqlalchemy.orm.exc import NoResultFound

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
    def json_header(self):
        return { "Content-Type": "application/json" }

    def setUp(self):
        # disable certificate warnings for testing
        requests.packages.urllib3.disable_warnings()

    def tearDown(self):
        email = "sample@fake.com"
        try:
            user = passzero.get_account_with_email(email)
            assert user is not None
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
        assert auth_response is not None
        assert auth_response.status_code == 200

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
        assert entry_create_response is not None
        assert entry_create_response.status_code == 200
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
            assert entry_create_response is not None
            assert entry_create_response.status_code == 403

            entries = self._get_entries(s)
            assert entries == []
        passzero.delete_account(user)

    def test_create_entry(self):
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
                "csrf_token": token
            }
            entry_id = self._create_entry(s, entry)
            entries = self._get_entries(s)
            assert len(entries) == 1
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


if __name__ == '__main__':
    unittest.main()
