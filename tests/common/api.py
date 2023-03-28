import copy
import json
import logging
import os
from typing import Dict, List, Optional, Union

import flask
import flask.testing
import requests
import six

json_header = {"Content-Type": "application/json"}
file_upload_headers = {"Content-Type": "multipart/form-data"}
BASE_URL = os.environ.get("LIVE_TEST_HOST", "https://localhost:5050")


logger = logging.getLogger(__name__)


class BadStatusCodeException(Exception):
    def __init__(self, status_code: int):
        super()
        self.status_code = status_code


def _is_requests_session(session) -> bool:
    """
    FIXME: massive hack to allow use of this file in end-to-end tests
    """
    return "requests" in str(type(session))


def _get_response_data(session, response: Union[requests.Response, flask.Response]) -> str:
    """
    FIXME: massive hack to allow use of this file in end-to-end tests
    """
    if _is_requests_session(session):
        assert isinstance(response, requests.Response)
        return response.text
    else:
        assert isinstance(response, flask.Response)
        return response.data


def _get_response_json(response: Union[requests.Response, flask.Response]) -> dict:
    """
    FIXME: massive hack to allow use of this file in end-to-end tests
    """
    if isinstance(response, requests.Response):
        return response.json()
    else:
        assert isinstance(response, flask.Response)
        j = response.get_json()
        assert j is not None
        return j


def _print_if_test(session, data) -> None:
    """
    FIXME: massive hack to allow use of this file in end-to-end tests
    """
    if not _is_requests_session(session):
        print(data)


def _print_response_text_if_test(response: Union[requests.Response, flask.Response]) -> None:
    """
    FIXME: massive hack to allow use of this file in end-to-end tests
    """
    if isinstance(response, flask.Response):
        print(response.data)


def json_header_with_token(token: str) -> Dict[str, str]:
    assert token is not None
    h = copy.copy(json_header)
    h["Authorization"] = f"Bearer {token}"
    return h


def json_get(session, relative_url: str, token: Optional[str] = None, verify: bool = False):
    if token:
        headers = json_header_with_token(token)
    else:
        headers = json_header
    # FIXME: massive hack around unit test vs real test
    kwargs = {}
    url = relative_url
    if _is_requests_session(session):
        url = BASE_URL + relative_url
        kwargs["verify"] = verify
    else:
        kwargs["follow_redirects"] = True
    return session.get(
        url,
        headers=headers,
        **kwargs
    )


def json_post(session: flask.testing.FlaskClient | requests.Session, relative_url: str, data: dict = {},
              token: Optional[str] = None, verify: bool = False):
    if token:
        headers = json_header_with_token(token)
    else:
        headers = json_header
    url = relative_url
    if _is_requests_session(session):
        assert isinstance(session, requests.Session)
        url = BASE_URL + relative_url
        return session.post(
            url,
            data=json.dumps(data),
            headers=headers,
            verify=True,
        )
    else:
        assert isinstance(session, flask.testing.FlaskClient)
        return session.post(
            url,
            data=json.dumps(data),
            headers=headers,
            follow_redirects=True,
        )


def json_put(session, relative_url: str, data: dict = {}, token: Optional[str] = None):
    if token:
        headers = json_header_with_token(token)
    else:
        headers = json_header
    # FIXME: massive hack around unit test vs real test
    kwargs = {}
    url = relative_url
    if _is_requests_session(session):
        url = BASE_URL + relative_url
        kwargs["verify"] = False
    else:
        kwargs["follow_redirects"] = True
    return session.put(
        url,
        data=json.dumps(data),
        headers=headers,
        **kwargs
    )


def json_patch(session, relative_url: str, data: dict = {}, token: Optional[str] = None):
    """
    :param token: The JWT Bearer token - leave out if you're not using it
    """
    if token:
        headers = json_header_with_token(token)
    else:
        headers = json_header
    # FIXME: massive hack around unit test vs real test
    kwargs = {}
    url = relative_url
    if _is_requests_session(session):
        # real tests (end to end) go here
        url = BASE_URL + relative_url
        kwargs["verify"] = False
    else:
        # unit tests go here
        kwargs["follow_redirects"] = True
    return session.patch(
        url,
        data=json.dumps(data),
        headers=headers,
        **kwargs
    )


def json_delete(session, relative_url: str, data: Optional[dict] = None, token: Optional[str] = None):
    """
    :param token: bearer token
    TODO for now data should reside in the URL
    """
    if data is None:
        data = {}
    if token:
        headers = json_header_with_token(token)
    else:
        headers = json_header
    # FIXME: massive hack around unit test vs real test
    kwargs = {}
    url = relative_url
    if _is_requests_session(session):
        url = BASE_URL + relative_url
        kwargs["verify"] = False
    else:
        kwargs["follow_redirects"] = True
    return session.delete(
        url,
        headers=headers,
        json=data,
        **kwargs
    )


# v1 API starts here


def login_v1(app, email: str, password: str, check_status: bool = True):
    assert isinstance(email, six.text_type)
    assert isinstance(password, six.text_type)
    assert isinstance(check_status, bool)
    data = {
        "email": email,
        "password": password
    }
    url = "/api/v1/login"
    r = json_post(app, url, data)
    _print_if_test(app, _get_response_data(app, r))
    if check_status:
        assert r.status_code == 200, "Failed to login with email '%s' and password '%s' (code %d)" % (
            email, password, r.status_code)
    return r


def logout_v1(app, check_status: bool = False):
    url = "/api/v1/logout"
    r = json_post(app, url)
    if check_status:
        assert r.status_code == 200
    return r


def get_csrf_token(app):
    """Always verifies status"""
    url = "/api/v1/csrf_token"
    r = json_get(app, url)
    assert r.status_code == 200
    token = _get_response_json(r)
    _print_if_test(app, "[client] received csrf_token: %s" % token)
    return token


def get_user_preferences_v1(app, check_status: bool = True):
    assert isinstance(check_status, bool)
    url = "/api/v1/user/preferences"
    r = json_get(app, url)
    if check_status:
        assert r.status_code == 200
        return _get_response_json(r)
    else:
        return r


def put_user_preferences(app, prefs: dict, csrf_token: str,
                         check_status: bool = True):
    assert isinstance(prefs, dict)
    assert isinstance(csrf_token, six.text_type)
    assert isinstance(check_status, bool)
    url = "/api/v1/user/preferences"
    data = copy.copy(prefs)
    data["csrf_token"] = csrf_token
    if _is_requests_session(app):
        url = BASE_URL + url
        r = app.put(url,
                    data=json.dumps(data),
                    headers=json_header,
                    verify=False)
    else:
        r = app.put(url,
                    data=json.dumps(data),
                    headers=json_header,
                    follow_redirects=True)
    if check_status:
        _print_if_test(app, _get_response_data(app, r))
        assert r.status_code == 200
    return r


def delete_user_v1(app, password: str, csrf_token: str,
                   check_status: bool = True):
    assert isinstance(password, six.text_type)
    assert isinstance(csrf_token, six.text_type)
    assert isinstance(check_status, bool)
    url = "/api/v1/user"
    r = app.delete(url,
                   data=json.dumps({
                       "csrf_token": csrf_token,
                       "password": password
                   }),
                   headers=json_header, follow_redirects=True)
    _print_if_test(app, _get_response_data(app, r))
    if check_status:
        assert r.status_code == 200
    return r


def user_signup_v1(app, email: str, password: str, check_status: bool = False):
    assert isinstance(email, six.text_type)
    assert isinstance(password, six.text_type)
    assert isinstance(check_status, bool)
    url = "/api/v1/user/signup"
    data = {
        "email": email,
        "password": password,
        "confirm_password": password
    }
    r = json_post(app, url, data)
    _print_if_test(app, _get_response_data(app, r))
    if check_status:
        assert r.status_code == 200
    return r


def recover_account_v1(app, email: str, csrf_token: str):
    url = "/api/v1/user/recover"
    data = {
        "email": email,
        "csrf_token": csrf_token
    }
    r = json_post(app, url, data)
    _print_if_test(app, _get_response_data(app, r))
    assert r.status_code == 200
    return r


def recover_account_confirm_v1(app, password: str, recovery_token: str,
                               csrf_token: str, check_status: bool = True):
    url = "/api/v1/user/recover/confirm"
    data = {
        "password": password,
        "confirm_password": password,
        "csrf_token": csrf_token,
        "token": recovery_token
    }
    r = json_post(app, url, data)
    _print_if_test(app, _get_response_data(app, r))
    if check_status:
        assert r.status_code == 200
    return r


def activate_account_v1(app, token: six.text_type, check_status: bool = True):
    assert isinstance(token, six.text_type)
    assert isinstance(check_status, bool)
    url = "/api/v1/user/activate"
    data = {"token": token}
    r = json_post(app, url, data)
    _print_if_test(app, _get_response_data(app, r))
    if check_status:
        assert r.status_code == 200
    return r


def update_user_password_v1(app, old_password: str, new_password: str,
                            csrf_token: str, check_status: bool = True):
    url = "/api/v1/user/password"
    data = {
        "csrf_token": csrf_token,
        "old_password": old_password,
        "new_password": new_password,
        "confirm_new_password": new_password
    }
    r = app.put(url,
                data=json.dumps(data),
                headers=json_header,
                follow_redirects=True)
    if check_status:
        _print_if_test(app, _get_response_data(app, r))
        assert r.status_code == 200
    return r

# documents


def get_documents(app, check_status: bool = True):
    url = "/api/v1/docs"
    r = json_get(app, url)
    if check_status:
        _print_if_test(app, _get_response_data(app, r))
        assert r.status_code == 200
        return _get_response_json(r)
    else:
        return r


def post_document(app, doc_params: dict, csrf_token: str,
                  check_status: bool = True):
    """
    if check_status is set, verify the status the return the document_id
    if check_status is set to False, return the response object
    """
    url = "/api/v1/docs"
    if _is_requests_session(app):
        url = BASE_URL + url
        data = {
            "csrf_token": csrf_token,
            "name": doc_params.pop("name"),
            "mimetype": doc_params.pop("mimetype")
        }
        r = app.post(
            url,
            data=data,
            files=doc_params,
            verify=False
        )
    else:
        doc_params["csrf_token"] = csrf_token
        r = app.post(
            url,
            data=doc_params,
            headers=file_upload_headers,
            follow_redirects=True
        )
    if check_status:
        _print_if_test(app, f"[post_document] status code = {r.status_code}")
        _print_if_test(app, _get_response_data(app, r))
        assert r.status_code == 200
        return _get_response_json(r)["document_id"]
    return r


def get_document(app, doc_id: int, check_status: bool = True):
    """Document will be served as a file from memory
    Response is the response object"""
    url = f"/api/v1/docs/{doc_id}"
    r = json_get(app, url)
    if check_status:
        _print_if_test(app, _get_response_data(app, r))
        assert r.status_code == 200
    return r


def update_document(app, doc_id: int, doc_params: dict, csrf_token: str,
                    check_status: bool = True):
    """Edit the document and return the raw response"""
    url = f"/api/v1/docs/{doc_id}"
    doc_params["csrf_token"] = csrf_token
    # this is a hack around the fact that app may come from 2 different places
    kwargs = {}
    if _is_requests_session(app):
        url = BASE_URL + url
        kwargs["verify"] = False
    else:
        kwargs["follow_redirects"] = True
    r = app.patch(
        url,
        data=doc_params,
        headers=file_upload_headers,
        **kwargs,
    )
    _print_if_test(app, _get_response_data(app, r))
    if check_status:
        assert r.status_code == 200, r.status_code
    return r


def delete_document(app, doc_id: int, csrf_token: str,
                    check_status: bool = True):
    url = f"/api/v1/docs/{doc_id}?csrf_token={csrf_token}"
    r = json_delete(app, url)
    _print_if_test(app, _get_response_data(app, r))
    if check_status:
        assert r.status_code == 200
    return r


# --- v3 (tokens) starts here


def get_api_token_with_login(session, check_status: bool = True):
    url = "/api/v3/token"
    r = json_get(session, url)
    response_data = _get_response_data(session, r)
    _print_if_test(session, response_data)
    if check_status:
        assert r.status_code == 200
        return _get_response_json(r)["token"]
    else:
        return r


def login_with_email_with_token(session, email: str, password: str,
                                check_status: bool = True, verify: bool = False):
    assert isinstance(email, str)
    url = "/api/v3/token"
    r = json_post(session, url, data={
        "email": email,
        "password": password
    }, verify=verify)
    response_data = _get_response_data(session, r)
    _print_if_test(session, response_data)
    try:
        if check_status:
            assert r.status_code == 200
            return _get_response_json(r)["token"]
        else:
            return r
    except AssertionError:
        raise BadStatusCodeException(r.status_code)


def login_with_username_with_token(session, username: str, password: str, check_status: bool = True,
                                   verify: bool = False):
    assert isinstance(username, str)
    url = "/api/v3/token"
    r = json_post(session, url, data={
        "username": username,
        "password": password
    }, verify=verify)
    response_data = _get_response_data(session, r)
    _print_if_test(session, response_data)
    try:
        if check_status:
            assert r.status_code == 200
            return _get_response_json(r)["token"]
        else:
            return r
    except AssertionError:
        raise BadStatusCodeException(r.status_code)


def delete_token(session, token: str, check_status: bool = True):
    """Equivalent to logout"""
    url = "/api/v3/token"
    r = json_delete(session, url, token=token)
    response_data = _get_response_data(session, r)
    _print_if_test(session, response_data)
    if check_status:
        assert r.status_code == 200
    return r


def create_entry_with_token(session, entry: dict, password: str, token: str, check_status: bool = True):
    url = "/api/v3/entries"
    data = {
        "entry": entry,
        "password": password
    }
    r = json_post(session, url, data=data, token=token)
    response_data = _get_response_data(session, r)
    _print_if_test(session, response_data)
    if check_status:
        assert r.status_code == 200
        return _get_response_json(r)["entry_id"]
    else:
        return r


def delete_all_entries_with_token(session, password: str, token: str, check_status: bool = True):
    url = "/api/v3/entries"
    r = json_delete(session, url, data={
        "password": password,
    }, token=token)
    response_data = _get_response_data(session, r)
    _print_if_test(session, response_data)
    if check_status:
        assert r.status_code == 200
    return r


def get_encrypted_entries_with_token(session, token: str, check_status: bool = True, verify: bool = False):
    """
    Return entry metadata without decrypting the entries
    """
    url = "/api/v3/entries"
    r = json_get(session, url, token=token, verify=verify)
    # will not be printed unless there is an error
    response_data = _get_response_data(session, r)
    _print_if_test(session, response_data)
    if check_status:
        assert r.status_code == 200
        return _get_response_json(r)
    else:
        return r


def delete_entry_with_token(session, entry_id: int, password: str, token: str, check_status: bool = True):
    url = f"/api/v3/entries/{entry_id}"
    data = {"password": password}
    r = json_delete(session, url, data=data, token=token)
    response_data = _get_response_data(session, r)
    _print_if_test(session, response_data)
    if check_status:
        assert r.status_code == 200
    return r


def decrypt_entry_with_token(session,
                             entry_id: int,
                             password: str,
                             token: str,
                             check_status: bool = True,
                             verify: bool = False):
    assert isinstance(entry_id, int)
    assert isinstance(password, str) and password != ""
    assert isinstance(token, str)
    assert isinstance(check_status, bool)
    url = f"/api/v3/entries/{entry_id}"
    r = json_post(
        session,
        url,
        {"password": password},
        token=token,
        verify=verify
    )
    response_data = _get_response_data(session, r)
    # will not be printed unless there is an error
    _print_if_test(session, response_data)
    if check_status:
        assert r.status_code == 200
        return json.loads(response_data)
    else:
        return r


def edit_entry_with_token(session,
                          entry_id: int,
                          new_entry: dict,
                          password: str,
                          token: str,
                          check_status: bool = True):
    assert isinstance(token, str)
    url = f"/api/v3/entries/{entry_id}"
    r = json_patch(
        session,
        url,
        {"entry": new_entry, "password": password},
        token=token
    )
    response_data = _get_response_data(session, r)
    _print_if_test(session, response_data)
    if check_status:
        assert r.status_code == 200
        return _get_response_json(r)
    else:
        return r


# API classes

class ApiV3:
    def __init__(self, client, base_url: Optional[str] = None) -> None:
        """
        :param client: Client object must be a request session or similar.
        """
        self.api_token = None  # type: Optional[str]
        self.client = client
        self.password = None  # type: Optional[str]
        if base_url:
            global BASE_URL
            BASE_URL = base_url
        logger.debug("Using BASE_URL %s", BASE_URL)

    def get_status(self):
        return self.json_get("/api/v3/status", check_status=True, use_token=False)

    def login(self, email: str, password: str, verify: bool = False) -> None:
        """Always checks status
        :param verify: Verify SSL cert
        """
        assert isinstance(email, str)
        assert isinstance(password, str) and password != ""
        token = login_with_email_with_token(self.client, email, password, check_status=True, verify=verify)
        self.api_token = token
        self.password = password

    def logout(self) -> None:
        assert self.api_token is not None
        delete_token(
            self.client,
            self.api_token,
            check_status=True
        )
        self.api_token = None
        self.password = None

    def json_post(self, url: str, data: dict, check_status: bool = True,
                  use_token: bool = True):
        if use_token:
            assert self.api_token is not None
        r = json_post(
            self.client,
            url,
            data=data,
            token=(self.api_token if use_token else None)
        )
        response_data = _get_response_data(self.client, r)
        _print_if_test(self.client, response_data)
        try:
            if check_status:
                assert r.status_code == 200
                return json.loads(response_data)
            else:
                return r
        except AssertionError:
            raise BadStatusCodeException(r.status_code)

    def json_get(self, url: str, check_status: bool = True, use_token: bool = True):
        if use_token:
            assert self.api_token is not None
            r = json_get(self.client, url, token=self.api_token)
        else:
            r = json_get(self.client, url)
        _print_if_test(self.client, _get_response_data(self.client, r))
        if check_status:
            assert r.status_code == 200
            return _get_response_json(r)
        else:
            return r

    def json_patch(self, url: str, data: dict, check_status: bool = True):
        """Always send the API token in the Authorization field"""
        assert self.api_token is not None
        r = json_patch(self.client, url, data=data, token=self.api_token)
        _print_if_test(self.client, _get_response_data(self.client, r))
        if check_status:
            assert r.status_code == 200
            return _get_response_json(r)
        else:
            return r

    def json_delete(self, url: str, data: Optional[dict] = None, check_status: bool = True):
        assert self.api_token is not None
        r = json_delete(self.client, url, token=self.api_token, data=data)
        _print_if_test(self.client, _get_response_data(self.client, r))
        try:
            if check_status:
                assert r.status_code == 200
                return _get_response_json(r)
            else:
                return r
        except AssertionError:
            raise BadStatusCodeException(r.status_code)

    # entries

    def get_encrypted_entries(self, verify: bool = False):
        assert self.api_token is not None
        return get_encrypted_entries_with_token(
            self.client,
            self.api_token,
            check_status=True,
            verify=verify
        )

    def decrypt_entry(self, entry_id: int, verify: bool = False):
        assert self.api_token is not None
        assert self.password is not None
        return decrypt_entry_with_token(
            self.client,
            entry_id,
            self.password,
            self.api_token,
            check_status=True,
            verify=verify
        )

    def create_entry(self, entry: dict) -> int:
        assert self.password is not None
        url = "/api/v3/entries"
        data = {
            "entry": entry,
            "password": self.password
        }
        return self.json_post(
            url=url,
            data=data,
            check_status=True
        )["entry_id"]

    def edit_entry(self, entry_id: int, new_entry: dict) -> None:
        assert self.password is not None
        assert self.api_token is not None
        url = f"/api/v3/entries/{entry_id}"
        data = {
            "entry": new_entry,
            "password": self.password,
        }
        self.json_patch(
            url,
            data=data,
            check_status=True
        )

    def update_entry_versions(self) -> int:
        """Always check status"""
        url = "/api/v3/entries"
        assert self.password is not None
        assert self.api_token is not None
        response_json = self.json_patch(url, {
            "password": self.password
        }, check_status=True)
        return response_json["num_updated"]

    # link

    def create_link(self, link: dict) -> int:
        """Always verifies status
        :returns: The link ID"""
        assert self.password is not None
        url = "/api/v3/links"
        data = {
            "link": link,
            "password": self.password
        }
        return self.json_post(
            url=url,
            data=data,
            check_status=True
        )["link_id"]

    def decrypt_link(self, link_id: int) -> dict:
        assert self.password is not None
        url = f"/api/v3/links/{link_id}"
        data = {
            "password": self.password
        }
        return self.json_post(
            url=url,
            data=data,
            check_status=True
        )

    def get_encrypted_links(self) -> List[dict]:
        url = "/api/v3/links"
        return self.json_get(
            url=url,
            check_status=True
        )

    def delete_link(self, link_id: int) -> None:
        assert self.password is not None and self.password != ""
        url = f"/api/v3/links/{link_id}"
        data = {
            "password": self.password,
        }
        self.json_delete(
            url=url,
            check_status=True,
            data=data,
        )

    def edit_link(self, link_id: int, new_link: dict) -> None:
        assert self.password is not None and self.password != ""
        url = f"/api/v3/links/{link_id}"
        data = {
            "link": new_link,
            "password": self.password
        }
        self.json_patch(
            url=url,
            data=data,
            check_status=True
        )

    def decrypt_links(self, link_ids: List[int],
                      password: Optional[str] = None, check_status: bool = True) -> list | flask.Response:
        """
        :param password: password is optional. if not provided, will use `self.password` (useful for testing)
        :param check_status: defaults to check_status=True unless stated otherwise
        """
        assert self.password is not None
        if password is None:
            password = self.password
        url = "/api/v3/links/decrypt"
        data = {
            "password": password,
            "link_ids": link_ids
        }
        return self.json_post(
            url=url,
            data=data,
            check_status=check_status
        )

    # services

    def get_services(self) -> List[dict]:
        url = "/api/v3/services"
        return self.json_get(url=url, check_status=True, use_token=False)["services"]

    # user

    def get_current_user(self) -> dict:
        url = "/api/v3/user/me"
        return self.json_get(url=url, check_status=True, use_token=True)

    def patch_current_user(self, data: dict, check_status: bool = True) -> dict | flask.Response:
        url = "/api/v3/user/me"
        return self.json_patch(url=url, data=data, check_status=check_status)
