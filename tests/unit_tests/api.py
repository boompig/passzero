import copy
import json
import logging

import six
from typing import Dict, List, Optional

json_header = {"Content-Type": "application/json"}
file_upload_headers = {"Content-Type": "multipart/form-data"}
BASE_URL = "http://localhost:5050"


logger = logging.getLogger(__name__)


class BadStatusCodeException(Exception):
    pass


def _is_requests_session(session) -> bool:
    """
    FIXME: massive hack to allow use of this file in end-to-end tests
    """
    return "requests" in str(type(session))


def _get_response_data(session, response) -> str:
    """
    FIXME: massive hack to allow use of this file in end-to-end tests
    """
    if _is_requests_session(session):
        return response.text
    else:
        return response.data


def _print_if_test(session, data) -> None:
    """
    FIXME: massive hack to allow use of this file in end-to-end tests
    """
    if not _is_requests_session(session):
        print(data)


def json_header_with_token(token: str) -> Dict[str, str]:
    assert token is not None
    h = copy.copy(json_header)
    h["Authorization"] = f"Bearer {token}"
    return h


def json_get(session, relative_url: str, token: Optional[str] = None):
    if token:
        headers = json_header_with_token(token)
    else:
        headers = json_header
    # FIXME: massive hack around unit test vs real test
    kwargs = {}
    url = relative_url
    if _is_requests_session(session):
        url = BASE_URL + relative_url
    else:
        kwargs["follow_redirects"] = True
    return session.get(
        url,
        headers=headers,
        **kwargs
    )


def json_post(session, relative_url: str, data: dict = {}, token: Optional[str] = None):
    if token:
        headers = json_header_with_token(token)
    else:
        headers = json_header
    # FIXME: massive hack around unit test vs real test
    kwargs = {}
    url = relative_url
    if _is_requests_session(session):
        url = BASE_URL + relative_url
    else:
        kwargs["follow_redirects"] = True
    return session.post(
        url,
        data=json.dumps(data),
        headers=headers,
        **kwargs
    )


def json_put(session, relative_url: str, data: dict = {}, token: Optional[str] = None):
    if token:
        headers = json_header_with_token(token)
    else:
        headers = json_header
    return session.put(
        relative_url,
        data=json.dumps(data),
        headers=headers,
        follow_redirects=True
    )


def json_patch(session, relative_url: str, data: dict = {}, token: Optional[str] = None):
    if token:
        headers = json_header_with_token(token)
    else:
        headers = json_header
    return session.patch(
        relative_url,
        data=json.dumps(data),
        headers=headers,
        follow_redirects=True
    )


def json_delete(session, relative_url: str, token: Optional[str] = None):
    if token:
        headers = json_header_with_token(token)
    else:
        headers = json_header
    # expect the data to be formatted into the URL for now
    return session.delete(
        relative_url,
        headers=headers,
        follow_redirects=True
    )


# v1 API starts here

def login(app, email: str, password: str, check_status: bool = True):
    assert isinstance(email, six.text_type)
    assert isinstance(password, six.text_type)
    assert isinstance(check_status, bool)
    data = {
        "email": email,
        "password": password
    }
    r = json_post(app, "/api/v1/login", data)
    print(r.data)
    if check_status:
        assert r.status_code == 200, "Failed to login with email '%s' and password '%s' (code %d)" % (
            email, password, r.status_code)
    return r


def logout(app, check_status=False):
    r = json_post(app, "/api/v1/logout")
    if check_status:
        assert r.status_code == 200
    return r


def get_csrf_token(app):
    r = json_get(app, "/api/v1/csrf_token")
    assert r.status_code == 200
    token = json.loads(r.data)
    print("[client] received csrf_token: %s" % token)
    return token


def get_entries(app, check_status=True):
    r = json_get(app, "/api/v1/entries")
    if check_status:
        assert r.status_code == 200
        return json.loads(r.data)
    else:
        return r


def get_user_preferences(app, check_status=True):
    assert isinstance(check_status, bool)
    r = json_get(app, "/api/v1/user/preferences")
    if check_status:
        assert r.status_code == 200
        return json.loads(r.data)
    else:
        return r


def put_user_preferences(app, prefs, csrf_token, check_status=True):
    assert isinstance(prefs, dict)
    assert isinstance(csrf_token, six.text_type)
    assert isinstance(check_status, bool)
    url = "/api/v1/user/preferences"
    data = copy.copy(prefs)
    data["csrf_token"] = csrf_token
    r = app.put(url,
                data=json.dumps(data),
                headers=json_header,
                follow_redirects=True)
    if check_status:
        print(r.data)
        assert r.status_code == 200
    return r


def create_entry(app, entry: dict, csrf_token: str, check_status: bool = True) -> int:
    """
    :return entry_id:       The entry ID of the newly created entry
    """
    data = copy.copy(entry)
    data["csrf_token"] = csrf_token
    r = json_post(app, "/api/v1/entries", data)
    if check_status:
        print(r.data)
        assert r.status_code == 200
        return json.loads(r.data)["entry_id"]
    else:
        return r


def delete_entry(app, entry_id, csrf_token, check_status=True):
    assert isinstance(entry_id, int)
    assert isinstance(csrf_token, six.text_type)
    assert isinstance(check_status, bool)
    url = "/api/v1/entries/{}?csrf_token={}".format(
        entry_id, csrf_token)
    r = app.delete(url,
                   headers=json_header, follow_redirects=True)
    print(r.data)
    if check_status:
        assert r.status_code == 200
    return r


def delete_all_entries(app, csrf_token, check_status=True):
    assert isinstance(csrf_token, six.text_type)
    assert isinstance(check_status, bool)
    url = "/api/v1/entries/nuclear"
    data = {"csrf_token": csrf_token}
    r = json_post(app, url, data)
    print(r.data)
    if check_status:
        assert r.status_code == 200
    return r


def delete_user(app, password, csrf_token, check_status=True):
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
    print(r.data)
    if check_status:
        assert r.status_code == 200
    return r


def edit_entry(app, entry_id, entry, csrf_token, check_status=True):
    assert isinstance(entry_id, int)
    assert isinstance(csrf_token, six.text_type)
    assert isinstance(check_status, bool)
    url = "/api/v1/entries/{}".format(entry_id)
    data = entry
    data["csrf_token"] = csrf_token
    r = json_put(app, url, data)
    if check_status:
        assert r.status_code == 200
    return r


def signup(app, email: str, password: str, check_status: bool = False):
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
    print(r.data)
    if check_status:
        assert r.status_code == 200
    return r


def recover_account(app, email: str, csrf_token: str):
    url = "/api/v1/user/recover"
    data = {
        "email": email,
        "csrf_token": csrf_token
    }
    r = json_post(app, url, data)
    print(r.data)
    assert r.status_code == 200
    return r


def recover_account_confirm(app, password, recovery_token, csrf_token, check_status=True):
    url = "/api/v1/user/recover/confirm"
    data = {
        "password": password,
        "confirm_password": password,
        "csrf_token": csrf_token,
        "token": recovery_token
    }
    r = json_post(app, url, data)
    print(r.data)
    if check_status:
        assert r.status_code == 200
    return r


def activate_account(app, token: six.text_type, check_status: bool = True):
    assert isinstance(token, six.text_type)
    assert isinstance(check_status, bool)
    data = {"token": token}
    r = json_post(app, "/api/v1/user/activate", data)
    print(r.data)
    if check_status:
        assert r.status_code == 200
    return r


def update_user_password(app, old_password, new_password, csrf_token, check_status=True):
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
        print(r.data)
        assert r.status_code == 200
    return r


def get_documents(app, check_status=True):
    r = json_get(app, "/api/v1/docs")
    if check_status:
        print(r.data)
        assert r.status_code == 200
        return json.loads(r.data)
    else:
        return r


def post_document(app, doc_params: dict, csrf_token: str, check_status: bool = True):
    url = "/api/v1/docs"
    doc_params["csrf_token"] = csrf_token
    r = app.post(
        url,
        data=doc_params,
        headers=file_upload_headers,
        follow_redirects=True
    )
    if check_status:
        print("[post_document] status code = %d" % r.status_code)
        print(r.data)
        assert r.status_code == 200
    return r


def get_document(app, doc_id, check_status=True):
    url = "/api/v1/docs/%d" % doc_id
    r = json_get(app, url)
    if check_status:
        print(r.data)
        assert r.status_code == 200
        return json.loads(r.data)
    else:
        return r


def delete_document(app, doc_id, csrf_token, check_status=True):
    url = "/api/v1/docs/{}".format(doc_id)
    r = app.delete(url,
                   data=json.dumps({
                       "csrf_token": csrf_token
                   }),
                   headers=json_header, follow_redirects=True)
    print(r.data)
    if check_status:
        assert r.status_code == 200
    return r


# --- v2 API starts here

def get_entries_v2(app):
    r = json_get(app, "/api/v2/entries")
    assert r.status_code == 200
    print(r.data)
    return json.loads(r.data)


def get_entry_v2(app, entry_id, check_status=True):
    r = json_get(app, "/api/v2/entries/{}".format(entry_id))
    if check_status:
        assert r.status_code == 200
        print(r.data)
        return json.loads(r.data)
    else:
        return r

# --- v3 (tokens) starts here


def get_api_token_with_login(session, check_status: bool = True):
    r = json_get(session, "/api/v3/token")
    response_data = _get_response_data(session, r)
    _print_if_test(session, response_data)
    if check_status:
        assert r.status_code == 200
        return json.loads(response_data)["token"]
    else:
        return r


def login_with_token(session, email: str, password: str, check_status: bool = True):
    assert isinstance(email, str)
    r = json_post(session, "/api/v3/token", data={
        "email": email,
        "password": password
    })
    response_data = _get_response_data(session, r)
    _print_if_test(session, response_data)
    try:
        if check_status:
            assert r.status_code == 200
            return json.loads(response_data)["token"]
        else:
            return r
    except AssertionError:
        raise BadStatusCodeException(r.status_code)


def delete_token(session, token: str, check_status: bool = True):
    r = json_delete(session, "/api/v3/token", token=token)
    response_data = _get_response_data(session, r)
    _print_if_test(session, response_data)
    if check_status:
        assert r.status_code == 200
    return r


def create_entry_with_token(session, entry: dict, password: str, token: str, check_status: bool = True):
    data = {
        "entry": entry,
        "password": password
    }
    r = json_post(session, "/api/v3/entries", data=data, token=token)
    response_data = _get_response_data(session, r)
    _print_if_test(session, response_data)
    if check_status:
        assert r.status_code == 200
        return json.loads(response_data)["entry_id"]
    else:
        return r


def delete_all_entries_with_token(session, token: str, check_status: bool = True):
    r = json_delete(session, "/api/v3/entries", token=token)
    response_data = _get_response_data(session, r)
    _print_if_test(session, response_data)
    if check_status:
        assert r.status_code == 200
    return r


def get_encrypted_entries_with_token(session, token: str, check_status: bool = True):
    """
    Return entry metadata without decrypting the entries
    """
    r = json_get(session, "/api/v3/entries", token=token)
    # will not be printed unless there is an error
    response_data = _get_response_data(session, r)
    _print_if_test(session, response_data)
    if check_status:
        assert r.status_code == 200
        return json.loads(response_data)
    else:
        return r


def delete_entry_with_token(session, entry_id: int, token: str, check_status: bool = True):
    r = json_delete(session, "/api/v3/entries/%d" % entry_id, token=token)
    response_data = _get_response_data(session, r)
    _print_if_test(session, response_data)
    if check_status:
        assert r.status_code == 200
    return r


def decrypt_entry_with_token(session,
                             entry_id: int,
                             password: str,
                             token: str,
                             check_status: bool = True):
    assert isinstance(entry_id, int)
    assert isinstance(password, str) and password != ""
    assert isinstance(token, str)
    assert isinstance(check_status, bool)
    r = json_post(
        session,
        "/api/v3/entries/{}".format(entry_id),
        {"password": password},
        token=token
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
    r = json_patch(
        session,
        f"/api/v3/entries/{entry_id}",
        {"entry": new_entry, "password": password},
        token=token
    )
    response_data = _get_response_data(session, r)
    _print_if_test(session, response_data)
    if check_status:
        assert r.status_code == 200
        return json.loads(r.data)
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

    def login(self, email: str, password: str) -> None:
        assert isinstance(email, str)
        assert isinstance(password, str) and password != ""
        token = login_with_token(self.client, email, password, check_status=True)
        self.api_token = token
        self.password = password
        """
        assert isinstance(email, str)
        assert isinstance(password, str)
        assert password is not None and password != ""
        url = "/api/v3/token"
        data = {
            "email": email,
            "password": password
        }
        json_response = self.json_post(url, data, check_status=True, use_token=False)
        print(json_response)
        self.api_token = json_response["token"]
        """

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
        _print_if_test(self.client, r.data)
        if check_status:
            assert r.status_code == 200
            return json.loads(r.data)
        else:
            return r

    def json_patch(self, url: str, data: dict, check_status: bool = True):
        assert self.api_token is not None
        r = json_patch(self.client, url, data=data, token=self.api_token)
        _print_if_test(self.client, r.data)
        if check_status:
            assert r.status_code == 200
            return json.loads(r.data)
        else:
            return r

    def json_delete(self, url: str, check_status: bool = True):
        assert self.api_token is not None
        r = json_delete(self.client, url, token=self.api_token)
        _print_if_test(self.client, r.data)
        if check_status:
            assert r.status_code == 200
            return json.loads(r.data)
        else:
            return r

    # entries

    def get_encrypted_entries(self):
        assert self.api_token is not None
        return get_encrypted_entries_with_token(
            self.client,
            self.api_token,
            check_status=True
        )

    def decrypt_entry(self, entry_id: int):
        assert self.api_token is not None
        assert self.password is not None
        return decrypt_entry_with_token(
            self.client,
            entry_id,
            self.password,
            self.api_token,
            check_status=True
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

    # link

    def create_link(self, link: dict) -> int:
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
        url = f"/api/v3/links/{link_id}"
        self.json_delete(
            url=url,
            check_status=True
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

    # services

    def get_services(self) -> List[dict]:
        url = "/api/v3/services"
        return self.json_get(url=url, check_status=True, use_token=False)["services"]
