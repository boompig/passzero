import json
import urllib2
import unittest
import requests
import passzero
from sqlalchemy.exc import IntegrityError

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
        requests.packages.urllib3.disable_warnings()

    def test_wrong_login(self):
        result = json_post(
            url=self.base_url + "/api/login",
            data={
                "email": "daniel@slav.slv",
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
        email = "dbkats@fake.com"
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


if __name__ == '__main__':
    unittest.main()
