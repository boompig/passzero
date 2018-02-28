import json
import os

import six
from requests import Response

json_header = { "Content-Type": "application/json" }
file_upload_headers = { "Content-Type": "multipart/form-data" }

assert 'LIVE_TEST_HOST' in os.environ, \
    "Did not find 'LIVE_TEST_HOST' among environment variables"
base_url = os.environ['LIVE_TEST_HOST']


### utils
def json_get(session, relative_url, data={}) -> Response:
    return session.get(
        base_url + relative_url,
        data=json.dumps(data),
        headers=json_header,
        verify=False
    )

def json_post(session, relative_url: str, data: dict = {}) -> Response:
    return session.post(
        base_url + relative_url,
        data=json.dumps(data),
        headers=json_header,
        verify=False
    )

def json_put(session, relative_url: str, data: dict = {}) -> Response:
    return session.put(
        base_url + relative_url,
        data=json.dumps(data),
        headers=json_header,
        verify=False
    )

def json_delete(session, relative_url: str) -> Response:
    # expect the data to be formatted into the URL for now
    return session.delete(
        base_url + relative_url,
        headers=json_header,
        verify=False
    )


### v1 API starts here

def login(session, email: str, password: str) -> Response:
    assert isinstance(email, six.text_type)
    assert isinstance(password, six.text_type)
    data={
        "email": email,
        "password": password
    }
    return json_post(session, "/api/v1/login", data)


def logout(session) -> Response:
    return json_post(session, "/api/v1/logout")


def get_csrf_token(session) -> Response:
    return json_get(session, "/api/v1/csrf_token")


def get_entries(session) -> Response:
    return json_get(session, "/api/v1/entries")


def create_entry(session, entry: dict, token: str) -> Response:
    assert isinstance(entry, dict)
    assert isinstance(token, six.text_type)
    data = entry
    data["csrf_token"] = token
    return json_post(session, "/api/v1/entries", data)


def delete_entry(session, entry_id: int, token: str) -> Response:
    assert isinstance(entry_id, int)
    assert isinstance(token, six.text_type)
    url = "/api/v1/entries/{}?csrf_token={}".format(
        entry_id, token)
    return json_delete(session, url)


def edit_entry(session, entry_id: int, entry: dict, token: str) -> Response:
    assert isinstance(entry_id, int)
    assert isinstance(entry, dict)
    assert isinstance(token, six.text_type)
    url = "/api/v1/entries/{}".format(entry_id)
    data = entry
    data["csrf_token"] = token
    return json_put(session, url, data)


def signup(session, email: str, password: str) -> Response:
    assert isinstance(email, six.text_type)
    assert isinstance(password, six.text_type)
    data = {
        "email": email,
        "password": password,
        "confirm_password": password
    }
    return json_post(session, "/api/v1/user/signup", data)


def recover(session, email: str, token: str) -> Response:
    assert isinstance(email, six.text_type)
    assert isinstance(token, six.text_type)
    data = {
        "email": email,
        "csrf_token": token
    }
    return json_post(session, "/api/v1/user/recover", data)


def get_documents(session) -> Response:
    return json_get(session, "/api/v1/docs")


def post_document(session, name: str, doc_params, csrf_token: str) -> Response:
    assert isinstance(name, six.text_type)
    assert isinstance(doc_params, dict)
    assert isinstance(csrf_token, six.text_type)
    url = base_url + "/api/v1/docs"
    r = session.post(url,
        data={"name": name, "csrf_token": csrf_token},
        files=doc_params,
        verify=False
    )
    return r


def get_document(session, doc_id: int) -> Response:
    assert isinstance(doc_id, int)
    url = "/api/v1/docs/%d" % doc_id
    return json_get(session, url)


def delete_document(session, doc_id: int, csrf_token: str) -> Response:
    assert isinstance(doc_id, int)
    assert isinstance(csrf_token, six.text_type)
    url = "/api/v1/docs/{}?csrf_token={}".format(doc_id, csrf_token)
    return json_delete(session, url)


#### v2 API starts here

def get_entries_v2(session) -> Response:
    return json_get(session, "/api/v2/entries")


def create_entry_v2(session, entry: dict, token: str) -> Response:
    assert isinstance(entry, dict)
    assert isinstance(token, six.text_type)
    entry["csrf_token"] = token
    return json_post(session, "/api/v2/entries", entry)


def delete_entry_v2(session, entry_id: int, token: str) -> Response:
    assert isinstance(entry_id, int)
    assert isinstance(token, six.text_type)
    url = "/api/v2/entries/{}?csrf_token={}".format(
        entry_id, token)
    return json_delete(session, url)

