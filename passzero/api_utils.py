import json
import logging
from functools import wraps

from flask import Response, abort, request, session

from .config import CSRF_TOKEN_LENGTH
from .crypto_utils import random_hex


def auth_or_abort(function):
    """This is a decorator which does authentication for GET requests to templates.
    If not authenticated, show the 401 screen.
    If authenticated, call the function."""
    @wraps(function)
    def inner(*args, **kwargs):
        if check_auth():
            return function(*args, **kwargs)
        else:
            return abort(401)
    return inner


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
        # make sure there is a CSRF token
        generate_csrf_token()
        if check_all_csrf():
            spend_csrf_token()
            return function(*args, **kwargs)
        else:
            code, data = json_csrf_validation_error()
            return write_json(code, data)
    return inner


def get_request_data():
    data = request.get_json(silent=True)
    if data:
        return data
    elif request.method == "POST" or request.method == "UPDATE":
        return request.form
    elif request.method == "DELETE" or request.method == "GET":
        return request.args
    else:
        abort(500)


def requires_json_form_validation(form_class):
    def real_function(function):
        @wraps(function)
        def inner(*args, **kwargs):
            request_data = get_request_data()
            form = form_class(data=request_data)
            if form.validate():
                return function(form.data, *args, **kwargs)
            else:
                code, data = json_form_validation_error(form.errors)
                return write_json(code, data)
        return inner
    return real_function


def spend_csrf_token():
    """Invalidate previous CSRF token and set a new one"""
    prev_token = session.pop("csrf_token")
    logging.debug("[spend_csrf_token] Previous csrf_token was %s" % prev_token)
    session["csrf_token"] = generate_csrf_token()


def generate_csrf_token():
    """Generate a CSRF token for the session, if not currently set"""
    if "csrf_token" not in session:
        session["csrf_token"] = random_hex(CSRF_TOKEN_LENGTH)
    return session["csrf_token"]


def write_json(code, data):
    """Write JSON response. Code is status code."""
    return Response(
        json.dumps(data, separators=(",", ":")),
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
    data = get_request_data()
    return check_csrf(data)


def check_csrf(form):
    """
    :return:     True iff csrf_token is set in the form and matches the CSRF token in session
    """
    return "csrf_token" in form and form["csrf_token"] == session["csrf_token"]


def json_csrf_validation_error():
    code, data = json_error(403, "Failed to validate CSRF token")
    return (code, data)


def json_internal_error(msg):
    """Return tuple of (code, JSON data)"""
    return json_error(500, msg)

