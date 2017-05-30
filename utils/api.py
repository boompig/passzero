import json
json_header = { "Content-Type": "application/json" }

### v1 API starts here
BASE_URL = ""

def login(app, email, password, check_status=True):
    data={
        "email": email,
        "password": password
    }
    r = app.post(BASE_URL + "/api/login",
        data=json.dumps(data),
        headers=json_header, allow_redirects=True)
    if check_status:
        assert r.status_code == 200
    return r


def logout(app):
    return app.post(BASE_URL + "/api/logout",
        headers=json_header, allow_redirects=True)


def get_csrf_token(app):
    r = app.get(BASE_URL + "/api/csrf_token",
        headers=json_header, allow_redirects=True)
    assert r.status_code == 200
    token = json.loads(r.text)
    # print("[client] received csrf_token: %s" % token)
    return token


def get_entries(app, check_status=True):
    r = app.get(BASE_URL + "/api/entries",
        headers=json_header, allow_redirects=True)
    if check_status:
        assert r.status_code == 200
        return json.loads(r.text)
    else:
        return r


def create_entry(app, entry, token, check_status=True):
    """
    :return entry_id:       The entry ID of the newly created entry
    """
    data = entry
    data["csrf_token"] = token
    r = app.post(BASE_URL + "/api/entries/new",
        data=json.dumps(data),
        headers=json_header, allow_redirects=True)
    if check_status:
        # print(r.text)
        assert r.status_code == 200
        return json.loads(r.text)["entry_id"]
    else:
        return r


def delete_entry(app, entry_id, token):
    url = BASE_URL + "/api/entries/{}?csrf_token={}".format(
        entry_id, token)
    r = app.delete(url,
        headers=json_header, allow_redirects=True)
    # print(r.text)
    assert r.status_code == 200
    return r


def edit_entry(app, entry_id, entry, token):
    url = BASE_URL + "/api/entries/{}".format(entry_id)
    data = entry
    data["csrf_token"] = token
    return app.post(BASE_URL + url,
        data=json.dumps(data),
        headers=json_header, allow_redirects=True)


def signup(app, email, password):
    url = BASE_URL + "/api/signup"
    data = {
        "email": email,
        "password": password,
        "confirm_password": password
    }
    return app.post(BASE_URL + url,
        data=json.dumps(data),
        headers=json_header, allow_redirects=True)


def recover_account(app, email, csrf_token):
    url = BASE_URL + "/api/v1/user/recover"
    data = {
        "email": email,
        "csrf_token": csrf_token
    }
    r = app.post(BASE_URL + url,
        data=json.dumps(data),
        headers=json_header, allow_redirects=True)
    print(r.text)
    assert r.status_code == 200
    return r


def recover_account_confirm(app, password, recovery_token, csrf_token):
    url = BASE_URL + "/api/v1/user/recover/confirm"
    data = {
        "password": password,
        "confirm_password": password,
        "csrf_token": csrf_token,
        "token": recovery_token
    }
    r = app.post(BASE_URL + url,
        data=json.dumps(data),
        headers=json_header, allow_redirects=True)
    print(r.text)
    assert r.status_code == 200
    return r


def activate_account(app, token):
    return app.post(BASE_URL + "/api/v1/signup/confirm",
        data=json.dumps({"token": token}),
        headers=json_header, allow_redirects=True)


def update_user_password(app, old_password, new_password, csrf_token, check_status=True):
    url = BASE_URL + "/api/v1/user/password"
    data = {
        "csrf_token": csrf_token,
        "old_password": old_password,
        "new_password": new_password,
        "confirm_new_password": new_password
    }
    r = app.put(url,
        data=json.dumps(data),
        headers=json_header,
        allow_redirects=True)
    if check_status:
        print(r.text)
        assert r.status_code == 200
    return r


#### v2 API starts here

def get_json(app, url):
    return app.get(
        url,
        headers=json_header,
        allow_redirects=True
    )


def get_entries_v2(app):
    r = get_json(app, BASE_URL + "/api/v2/entries")
    assert r.status_code == 200
    # print(r.text)
    return json.loads(r.text)


def get_entry_v2(app, entry_id, check_status=True):
    r = get_json(app, BASE_URL + "/api/v2/entries/{}".format(entry_id))
    if check_status:
        # print(r.text)
        assert r.status_code == 200
        return json.loads(r.text)
    else:
        return r