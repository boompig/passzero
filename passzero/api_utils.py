import json
from functools import wraps
from typing import Any, Dict, Optional, Tuple

from flask import Response, abort, request, session


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
            if request.files:
                # shouldn't pass in data directly here
                form = form_class()
            else:
                form = form_class(data=request_data)
            if form.validate():
                return function(form.data, *args, **kwargs)
            else:
                code, data = json_form_validation_error(form.errors)
                return write_json(code, data)
        return inner
    return real_function


def write_json(code: int, data: dict | str | list) -> Response:
    """Write JSON response. Code is status code."""
    return Response(
        json.dumps(data, separators=(",", ":")),
        status=code,
        mimetype="application/json"
    )


def json_form_validation_error(errors) -> Tuple[int, dict]:
    code, data = json_error(400, "Failed to validate form")
    for k, v in dict(errors).items():
        data[k] = v[0]
    return (code, data)


def json_error(code: int, msg: str) -> Tuple[int, dict]:
    return (code, {
        "status": "error",
        "msg": msg
    })


def json_error_v2(msg: str, http_status_code: int,
                  app_error_code: Optional[int] = None) -> Tuple[Dict[str, Any], int]:
    d = {
        "status": "error",
        "msg": msg
    }  # type: Dict[str, Any]
    if app_error_code:
        d["code"] = app_error_code
    return (d, http_status_code)


def json_success(msg: str) -> Tuple[int, dict]:
    """Return tuple of (code, JSON data)"""
    return (200, {
        "status": "success",
        "msg": msg
    })


def json_success_v2(msg: str) -> Tuple[dict, int]:
    """Return tuple of (code, JSON data)"""
    return ({
        "status": "success",
        "msg": msg
    }, 200)


def check_auth() -> bool:
    """Return True iff user_id and password are in session."""
    return 'user_id' in session and 'password' in session


def json_noauth() -> Tuple[int, dict]:
    """Return tuple of (code, json object)"""
    return json_error(401, "must be logged in to perform this action")


def json_internal_error(msg: str) -> Tuple[int, dict]:
    """Return tuple of (code, JSON data)"""
    return json_error(500, msg)
