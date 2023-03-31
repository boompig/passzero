import json
from typing import Dict
import copy
import requests

requests.packages.urllib3.disable_warnings()

# v1 API starts here
BASE_URL = ""
json_header = {"Content-Type": "application/json"}


def login_v1(app, email, password, check_status=True):
    data = {
        "email": email,
        "password": password
    }
    r = app.post(BASE_URL + "/api/v1/login",
                 data=json.dumps(data),
                 headers=json_header, allow_redirects=True)
    if check_status:
        assert r.status_code == 200
    return r


def logout_v1(app):
    return app.post(BASE_URL + "/api/v1/logout",
                    headers=json_header, allow_redirects=True)


# v3 API starts here


def get_json(app, url):
    return app.get(
        url,
        headers=json_header,
        allow_redirects=True
    )


def json_header_with_token(token: str) -> Dict[str, str]:
    assert token is not None
    h = copy.copy(json_header)
    h["Authorization"] = "Bearer %s" % token
    return h


def json_post(session, relative_url: str, data: dict = {}, token: str = None):
    if token:
        headers = json_header_with_token(token)
    else:
        headers = json_header
    return session.post(
        BASE_URL + relative_url,
        data=json.dumps(data),
        headers=headers,
        verify=False
    )


def json_get(session, relative_url: str, token: str = None):
    if token:
        headers = json_header_with_token(token)
    else:
        headers = json_header
    return session.get(
        BASE_URL + relative_url,
        headers=headers,
        verify=False
    )


# token stuff


def login_with_token(app, email: str, password: str, check_status: bool = True):
    r = json_post(app, "/api/v3/token", data={
        "email": email,
        "password": password
    })
    if check_status:
        assert r.status_code == 200
        return r.json()["token"]
    else:
        return r


def get_encrypted_entries_with_token(app, token: str, check_status: bool = True):
    r = json_get(app, "/api/v3/entries", token=token)
    if check_status:
        assert r.status_code == 200
        return r.json()
    else:
        return r
