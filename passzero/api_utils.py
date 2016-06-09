import json
from functools import wraps
from .crypto_utils import random_hex
from .config import CSRF_TOKEN_LENGTH
from flask import session, Response, request, abort


def requires_json_auth(function):
    """This is a decorator which does authentication for JSON requests.
    If not authenticated, return json_noauth.
    If authenticated, call the function."""
    @wraps(function)
    def inner(*args, **kwargs):
        if check_auth():
            return function(*args, **kwargs)
        else:
            code, data = json_noauth()
            return write_json(code, data)
    return inner


def requires_csrf_check(function):
    """This is a decorator which checks CSRF tokens for JSON requests.
    If not authenticated, return json_csrf_validation_error.
    If authenticated, call the function."""
    @wraps(function)
    def inner(*args, **kwargs):
        if check_all_csrf():
            return function(*args, **kwargs)
        else:
            code, data = json_csrf_validation_error()
            return write_json(code, data)
    return inner


def generate_csrf_token():
    """Generate a CSRF token for the session, if not currently set"""
    if "csrf_token" not in session:
        session["csrf_token"] = random_hex(CSRF_TOKEN_LENGTH)
    return session["csrf_token"]


def write_json(code, data):
    """Write JSON response. Code is status code."""
    return Response(
        json.dumps(data),
        status=code,
        mimetype="application/json"
    )


def json_form_validation_error(errors):
    code, data = json_error(400, "Failed to validate form")
    for k, v in dict(errors).iteritems():
        data[k] = v[0]
    return (code, data)


def json_error(code, msg):
    return (code, {
        "status": "error",
        "msg": msg
    })


def json_success(msg):
    """Return tuple of (code, JSON data)"""
    return (200, {
        "status": "success",
        "msg": msg
    })


def check_auth():
    """Return True iff user_id and password are in session."""
    return 'user_id' in session and 'password' in session


def json_noauth():
    """Return tuple of (code, json object)"""
    return json_error(401, "must be logged in to perform this action")


def check_all_csrf():
    """Check CSRF token differently depending on the request method"""
    data = request.get_json(silent=True)
    if data:
        return check_csrf(data)
    elif request.method == "POST" or request.method == "UPDATE":
        return check_csrf(request.form)
    elif request.method == "DELETE" or request.method == "GET":
        return check_csrf(request.args)
    else:
        return abort(500)


def check_csrf(form):
    """
    :return: True iff csrf_token is set form and matches the CSRF token in session"""
    return "csrf_token" in form and form["csrf_token"] == session["csrf_token"]


def json_csrf_validation_error():
    code, data = json_error(403, "Failed to validate CSRF token")
    return (code, data)


def json_internal_error(msg):
    """Return tuple of (code, JSON data)"""
    return json_error(500, msg)


