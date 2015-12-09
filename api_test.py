import json
import urllib2
import unittest
import requests
import passzero
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm.exc import NoResultFound
from requests import Request

"""
Very hacky API testing - runs on local server
"""


def json_post(url, data):
    data_json = json.dumps(data)
    headers = { "Content-Type": "application/json" }
    return requests.post(url, data_json, verify=False,
        headers=headers)


class PassZeroApiTester(unittest.TestCase):
    @property
    def base_url(self):
        return "https://127.0.0.1:5050"

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
        user = passzero.create_inactive_account(email, password)
        passzero.activate_account(user)
        result = json_post(
            url=self.base_url + "/api/login",
            data={
                "email": email,
                "password": password
            }
        )
        assert result is not None
        assert result.status_code == 200
        passzero.delete_account(user)

    def test_get_entries_empty(self):
        email = "sample@fake.com"
        password = "right_pass"
        user = passzero.create_inactive_account(email, password)
        passzero.activate_account(user)
        with requests.Session() as s:
            headers = { "Content-Type": "application/json" }
            data={
                "email": email,
                "password": password
            }
            auth_response = s.post(self.base_url + "/api/login",
                data=json.dumps(data), headers=headers,
                verify=False)
            assert auth_response is not None
            assert auth_response.status_code == 200
            entry_response = s.get(self.base_url + "/api/entries",
                headers=headers, verify=False)
            assert entry_response is not None
            assert entry_response.status_code == 200
            assert entry_response.json() is not None
            assert entry_response.json() == []
        passzero.delete_account(user)

    def test_create_no_csrf(self):
        email = "sample@fake.com"
        password = "right_pass"
        user = passzero.create_inactive_account(email, password)
        passzero.activate_account(user)
        with requests.Session() as s:
            headers = { "Content-Type": "application/json" }
            data={
                "email": email,
                "password": password
            }
            auth_response = s.post(self.base_url + "/api/login",
                data=json.dumps(data), headers=headers,
                verify=False)
            assert auth_response is not None
            assert auth_response.status_code == 200

            entry = {
                "account": "fake",
                "username": "entry_username",
                "password": "entry_pass",
            }
            entry_create_response = s.post(self.base_url + "/api/entries/new",
                data=json.dumps(entry),
                headers=headers, verify=False)
            assert entry_create_response is not None
            assert entry_create_response.status_code == 403

            entry_response = s.get(self.base_url + "/api/entries",
                headers=headers, verify=False)
            assert entry_response is not None
            assert entry_response.status_code == 200
            assert entry_response.json() is not None
            assert entry_response.json() == []
        passzero.delete_account(user)

    def test_create_entry(self):
        email = "sample@fake.com"
        password = "right_pass"
        user = passzero.create_inactive_account(email, password)
        passzero.activate_account(user)
        with requests.Session() as s:
            headers = { "Content-Type": "application/json" }
            data={
                "email": email,
                "password": password
            }
            auth_response = s.post(self.base_url + "/api/login",
                data=json.dumps(data), headers=headers,
                verify=False)
            assert auth_response is not None
            assert auth_response.status_code == 200

            csrf_response = s.get(self.base_url + "/api/csrf_token",
                headers=headers, verify=False)
            assert csrf_response is not None
            assert csrf_response.status_code == 200
            token = csrf_response.json()
            assert type(token) == unicode
            assert len(token) != 0

            entry = {
                "account": "fake",
                "username": "entry_username",
                "password": "entry_pass",
                "csrf_token": token
            }
            entry_create_response = s.post(self.base_url + "/api/entries/new",
                data=json.dumps(entry),
                headers=headers, verify=False)
            assert entry_create_response is not None
            assert entry_create_response.status_code == 200
            entry_id = entry_create_response.json()["entry_id"]
            assert type(entry_id) == int

            entry_response = s.get(self.base_url + "/api/entries",
                headers=headers, verify=False)
            assert entry_response is not None
            assert entry_response.status_code == 200
            assert entry_response.json() is not None
            assert type(entry_response.json()) == list
            assert len(entry_response.json()) == 1
        passzero.delete_account(user)

    def test_delete_entry(self):
        email = "sample@fake.com"
        password = "right_pass"
        user = passzero.create_inactive_account(email, password)
        passzero.activate_account(user)
        with requests.Session() as s:
            headers = { "Content-Type": "application/json" }
            data={
                "email": email,
                "password": password
            }
            auth_response = s.post(self.base_url + "/api/login",
                data=json.dumps(data), headers=headers,
                verify=False)
            assert auth_response is not None
            assert auth_response.status_code == 200

            csrf_response = s.get(self.base_url + "/api/csrf_token",
                headers=headers, verify=False)
            assert csrf_response is not None
            assert csrf_response.status_code == 200
            token = csrf_response.json()
            assert type(token) == unicode
            assert len(token) != 0

            entry = {
                "account": "fake",
                "username": "entry_username",
                "password": "entry_pass",
                "csrf_token": token
            }
            entry_create_response = s.post(self.base_url + "/api/entries/new",
                data=json.dumps(entry),
                headers=headers, verify=False)
            assert entry_create_response is not None
            assert entry_create_response.status_code == 200
            entry_id = entry_create_response.json()["entry_id"]
            assert type(entry_id) == int

            url = self.base_url + "/api/entries/{}?csrf_token={}".format(
                entry_id, token)
            entry_delete_response = s.delete(url,
                headers=headers, verify=False)
            assert entry_delete_response is not None
            assert entry_delete_response.status_code == 200

            entry_response = s.get(self.base_url + "/api/entries",
                headers=headers, verify=False)
            assert entry_response is not None
            assert entry_response.status_code == 200
            assert entry_response.json() is not None
            assert entry_response.json() == []
        passzero.delete_account(user)


if __name__ == '__main__':
    unittest.main()
