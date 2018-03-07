import copy
import json

import six
from typing import Dict

json_header = { "Content-Type": "application/json" }
file_upload_headers = { "Content-Type": "multipart/form-data" }


### utils

def json_header_with_token(token: str) -> Dict[str, str]:
    assert token is not None
    h = copy.copy(json_header)
    h["Authorization"] = "Bearer %s" % token
    return h

def json_get(app, relative_url: str, token: str = None):
    if token:
        headers = json_header_with_token(token)
    else:
        headers = json_header
    return app.get(
        relative_url,
        headers=headers,
        follow_redirects=True
    )

def json_post(session, relative_url: str, data: dict = {}, token: str = None):
    if token:
        headers = json_header_with_token(token)
    else:
        headers = json_header
    return session.post(
        relative_url,
        data=json.dumps(data),
        headers=headers,
        follow_redirects=True
    )

def json_put(session, relative_url: str, data: dict = {}, token: str = None):
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


def json_patch(session, relative_url: str, data: dict = {}, token: str = None):
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


def json_delete(session, relative_url: str, token: str = None):
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


### v1 API starts here

def login(app, email: str, password: str, check_status: bool = True):
    assert isinstance(email, six.text_type)
    assert isinstance(password, six.text_type)
    assert isinstance(check_status, bool)
    data={
        "email": email,
        "password": password
    }
    r = json_post(app, "/api/v1/login", data)
    print(r.data)
    if check_status:
        assert r.status_code == 200, "Failed to login with email '%s' and password '%s' (code %d)" % (email, password, r.status_code)
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
    data = { "csrf_token": csrf_token }
    r = json_post(app, url, data)
    print(r.data)
    if check_status:
        assert r.status_code == 200
    return r


def delete_user(app, password, csrf_token, check_status=True):
    assert isinstance(password, six.text_type)
    assert isinstance(csrf_token, six.text_type)
    assert isinstance(check_status, bool)
    url = "/api/v1/user".format(password, csrf_token)
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
    data = { "token": token }
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


def post_document(app, doc_params, csrf_token, check_status=True):
    url = "/api/v1/docs"
    doc_params["csrf_token"] = csrf_token
    r = app.post(url,
        data=doc_params,
        headers=file_upload_headers,
        follow_redirects=True)
    if check_status:
        print("status code = %d" % r.status_code)
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


#### v2 API starts here

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

#### v3 (tokens)

def get_api_token_with_login(app, check_status: bool = True):
    r = json_get(app, "/api/v3/token")
    print(r.data)
    if check_status:
        assert r.status_code == 200
        return json.loads(r.data)["token"]
    else:
        return r

def login_with_token(app, email: str, password: str, check_status: bool = True):
    r = json_post(app, "/api/v3/token", data={
        "email": email,
        "password": password
    })
    if check_status:
        print(r)
        print(r.status_code)
        assert r.status_code == 200
        print(json.loads(r.data))
        return json.loads(r.data)["token"]
    else:
        return r


def destroy_token(app, token: str, check_status: bool = True):
    r = json_delete(app, "/api/v3/token", token=token)
    print(r.data)
    if check_status:
        assert r.status_code == 200
    return r


def create_entry_with_token(app, entry: dict, password: str, token: str, check_status: bool = True):
    data = {
        "entry": entry,
        "password": password
    }
    r = json_post(app, "/api/v3/entries", data=data, token=token)
    if check_status:
        print(r.data)
        assert r.status_code == 200
        return json.loads(r.data)["entry_id"]
    else:
        return r


def delete_all_entries_with_token(app, token: str, check_status: bool = True):
    r = json_delete(app, "/api/v3/entries", token=token)
    print(r.data)
    if check_status:
        assert r.status_code == 200
    return r


def get_encrypted_entries_with_token(app, token: str, check_status: bool = True):
    r = json_get(app, "/api/v3/entries", token=token)
    print(r.data)
    if check_status:
        assert r.status_code == 200
        return json.loads(r.data)
    else:
        return r


def delete_entry_with_token(app, entry_id: int, token: str, check_status: bool = True):
    r = json_delete(app, "/api/v3/entries/%d" % entry_id, token=token)
    print(r.data)
    if check_status:
        assert r.status_code == 200
    return r


def decrypt_entry_with_token(app,
        entry_id: int,
        password: str,
        token: str,
        check_status: bool = True):
    r = json_post(
        app,
        "/api/v3/entries/{}".format(entry_id),
        { "password": password },
        token=token
    )
    if check_status:
        assert r.status_code == 200
        print(r.data)
        return json.loads(r.data)
    else:
        return r


def edit_entry_with_token(app,
        entry_id: int,
        new_entry: dict,
        password: str,
        token: str,
        check_status: bool = True):
    r = json_patch(
        app,
        "/api/v3/entries/{}".format(entry_id),
        { "entry": new_entry, "password": password },
        token=token
    )
    if check_status:
        assert r.status_code == 200
        print(r.data)
        return json.loads(r.data)
    else:
        return r


