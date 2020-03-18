import json
import os

import six
from requests import Response
from typing import Optional, Dict, List
import copy
import requests

json_header = {"Content-Type": "application/json"}
file_upload_headers = {"Content-Type": "multipart/form-data"}

assert 'LIVE_TEST_HOST' in os.environ, \
    "Did not find 'LIVE_TEST_HOST' among environment variables"
BASE_URL = os.environ['LIVE_TEST_HOST']


# utils
def json_header_with_token(token: str) -> Dict[str, str]:
    assert token is not None
    h = copy.copy(json_header)
    h["Authorization"] = "Bearer %s" % token
    return h


def json_get(session, relative_url: str, data: dict = {}, token: Optional[str] = None) -> Response:
    if token:
        headers = json_header_with_token(token)
    else:
        headers = json_header
    return session.get(
        BASE_URL + relative_url,
        data=json.dumps(data),
        headers=headers,
        verify=False
    )


def json_post(session, relative_url: str, data: dict = {}, token: Optional[str] = None) -> Response:
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


def json_put(session, relative_url: str, data: dict = {}, token: Optional[str] = None) -> Response:
    if token:
        headers = json_header_with_token(token)
    else:
        headers = json_header
    return session.put(
        BASE_URL + relative_url,
        data=json.dumps(data),
        headers=headers,
        verify=False
    )


def json_delete(session, relative_url: str, token: Optional[str] = None) -> Response:
    if token:
        headers = json_header_with_token(token)
    else:
        headers = json_header
    # expect the data to be formatted into the URL for now
    return session.delete(
        BASE_URL + relative_url,
        headers=headers,
        verify=False
    )


# v1 API starts here

def login(session, email: str, password: str) -> Response:
    assert isinstance(email, six.text_type)
    assert isinstance(password, six.text_type)
    data = {
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


def post_document(session, name: str, mimetype: str, doc_params: dict,
                  csrf_token: str) -> Response:
    assert isinstance(name, six.text_type)
    assert isinstance(mimetype, six.text_type)
    assert isinstance(doc_params, dict)
    assert isinstance(csrf_token, six.text_type)
    url = BASE_URL + "/api/v1/docs"
    r = session.post(url,
                     data={
                         "name": name,
                         "csrf_token": csrf_token,
                         "mimetype": mimetype},
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


# v2 API starts here

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


def get_entry_v2(session, entry_id: int) -> Response:
    return json_get(session, "/api/v2/entries/{}".format(entry_id))


# v3 API starts here
def login_with_token(session, email: str, password: str) -> Response:
    return json_post(session, "/api/v3/token", data={
        "email": email,
        "password": password
    })


def get_encrypted_entries_with_token(session, token: str) -> Response:
    """
    Return entry metadata without decrypting the entries
    """
    return json_get(session, "/api/v3/entries", token=token)


def decrypt_entry_with_token(session,
                             entry_id: int,
                             password: str,
                             token: str) -> Response:
    return json_post(
        session,
        "/api/v3/entries/{}".format(entry_id),
        data={"password": password},
        token=token
    )


def create_entry_with_token(session,
                            entry: dict,
                            password: str,
                            token: str) -> Response:
    data = {
        "entry": entry,
        "password": password
    }
    return json_post(session, "/api/v3/entries", data=data, token=token)


def delete_entry_with_token(session,
                            entry_id: int,
                            token: str) -> Response:
    return json_delete(session, "/api/v3/entries/%d" % entry_id, token=token)


class ApiClient:
    def __init__(self, base_url: str) -> None:
        global BASE_URL
        BASE_URL = base_url
        self.session = requests.Session()
        self.api_token = None

    def __assert_status_code_200(self, response: Response) -> None:
        try:
            assert response.status_code == 200
        except AssertionError as e:
            print("Expected status code 200. Got code {}".format(response.status_code))
            print(response.text)
            raise e

    def login(self, email: str, password: str) -> str:
        r = login_with_token(self.session, email, password)
        self.__assert_status_code_200(r)
        # save the token
        self.api_token = r.json()["token"]
        assert self.api_token is not None
        return self.api_token

    def get_encrypted_entries(self) -> List[dict]:
        assert self.api_token is not None
        r = get_encrypted_entries_with_token(self.session, self.api_token)
        self.__assert_status_code_200(r)
        return r.json()

    def decrypt_entry(self, entry_id: int, password: str) -> dict:
        assert self.api_token is not None
        r = decrypt_entry_with_token(self.session, entry_id, password, self.api_token)
        self.__assert_status_code_200(r)
        return r.json()

    def create_entry(self, new_entry: dict, password: str) -> int:
        assert self.api_token is not None
        r = create_entry_with_token(self.session, new_entry, password, self.api_token)
        self.__assert_status_code_200(r)
        return r.json()["entry_id"]

    def delete_entry(self, entry_id: int) -> dict:
        assert self.api_token is not None
        r = delete_entry_with_token(self.session, entry_id, self.api_token)
        self.__assert_status_code_200(r)
        return r.json()
