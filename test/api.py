import json

json_header = { "Content-Type": "application/json" }
base_url = "https://127.0.0.1:5050"


def login(session, email, password):
    data={
        "email": email,
        "password": password
    }
    return session.post(base_url + "/api/login",
        data=json.dumps(data), headers=json_header,
        verify=False)


def get_csrf_token(session):
    return session.get(base_url + "/api/csrf_token",
        headers=json_header, verify=False)


def get_entries(session):
    return session.get(base_url + "/api/entries",
        headers=json_header, verify=False)


def get_entries(session):
    return session.get(base_url + "/api/entries",
        headers=json_header, verify=False)


def create_entry(session, entry):
    return session.post(base_url + "/api/entries/new",
        data=json.dumps(entry),
        headers=json_header, verify=False)


def delete_entry(session, entry_id, token):
    url = base_url + "/api/entries/{}?csrf_token={}".format(
        entry_id, token)
    return session.delete(url,
        headers=json_header, verify=False)


def get_entries_v2(session):
    return session.get(base_url + "/api/v2/entries",
        headers=json_header, verify=False)


def create_entry_v2(session, entry):
    return session.post(base_url + "/api/v2/entries",
        data=json.dumps(entry),
        headers=json_header, verify=False)


def delete_entry_v2(session, entry_id, token):
    url = base_url + "/api/v2/entries/{}?csrf_token={}".format(
        entry_id, token)
    return session.delete(url,
        headers=json_header, verify=False)
