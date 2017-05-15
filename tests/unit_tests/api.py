import json
json_header = { "Content-Type": "application/json" }

### v1 API starts here

def login(app, email, password):
    data={
        "email": email,
        "password": password
    }
    r = app.post( "/api/login",
        data=json.dumps(data),
        headers=json_header, follow_redirects=True)
    assert r.status_code == 200
    return r


def logout(app):
    return app.post( "/api/logout",
        headers=json_header, follow_redirects=True)


def get_csrf_token(app):
    r = app.get("/api/csrf_token",
        headers=json_header, follow_redirects=True)
    assert r.status_code == 200
    token = json.loads(r.data)
    print("[client] received csrf_token: %s" % token)
    return token


def get_entries(app):
    r = app.get( "/api/entries",
        headers=json_header, follow_redirects=True)
    assert r.status_code == 200
    return json.loads(r.data)


def create_entry(app, entry, token):
    data = entry
    data["csrf_token"] = token
    r = app.post( "/api/entries/new",
        data=json.dumps(data),
        headers=json_header, follow_redirects=True)
    print(r.data)
    assert r.status_code == 200
    return json.loads(r.data)["entry_id"]


def delete_entry(app, entry_id, token):
    url = "/api/entries/{}?csrf_token={}".format(
        entry_id, token)
    r = app.delete(url,
        headers=json_header, follow_redirects=True)
    print(r.data)
    assert r.status_code == 200
    return r


def edit_entry(app, entry_id, entry, token):
    url = "/api/entries/{}".format(entry_id)
    data = entry
    data["csrf_token"] = token
    return app.post(url,
        data=json.dumps(data),
        headers=json_header, follow_redirects=True)


def signup(app, email, password):
    url = "/api/signup"
    data = {
        "email": email,
        "password": password,
        "confirm_password": password
    }
    return app.post(url,
        data=json.dumps(data),
        headers=json_header, follow_redirects=True)

def recover(app, email, token):
    url = "/api/recover"
    data = {
        "email": email,
        "csrf_token": token
    }
    return app.post(url,
        data=json.dumps(data),
        headers=json_header, follow_redirects=True)

#### v2 API starts here

def get_entries_v2(app):
    return app.get( "/api/v2/entries",
        headers=json_header, follow_redirects=True)


def create_entry_v2(app, entry, token):
    entry["csrf_token"] = token
    return app.post( "/api/v2/entries",
        data=json.dumps(entry),
        headers=json_header, follow_redirects=True)


def delete_entry_v2(app, entry_id, token):
    url = "/api/v2/entries/{}?csrf_token={}".format(
        entry_id, token)
    return app.delete(url,
        headers=json_header, follow_redirects=True)


def get_login_salt(app, email):
    url = "/api/v2/login_key_salt?email=%s" % email
    return app.get(url,
        headers=json_header, follow_redirects=True)


def login_v2(app, email, extended_key):
    url = "/api/v2/login"
    data = { "email": email, "extended_key": extended_key }
    return app.post(url,
        data=json.dumps(data),
        headers=json_header, follow_redirects=True)
