"""
This file will test whether the templates fetched can be rendered at all
"""

from __future__ import print_function

import logging
import os
from io import BytesIO
from unittest import mock

import flask
import pytest

from passzero.app_factory import create_app
from passzero.models import db

from . import api

DEFAULT_EMAIL = "sample@fake.com"
DEFAULT_PASSWORD = "right_pass"
TEMPLATE_FOLDER = os.path.realpath(os.path.dirname(__file__) + "/../../templates")


@pytest.fixture(scope="function")
def test_client():
    logging.basicConfig(level=logging.DEBUG)
    _app = create_app(__name__, {
        "SQLALCHEMY_DATABASE_URI": "sqlite://",
        "SQLALCHEMY_TRACK_MODIFICATIONS": False,
        "BUILD_ID": "test",
        "WTF_CSRF_ENABLED": False,
        "JSONIFY_PRETTYPRINT_REGULAR": False,
        "TESTING": True
    })

    # template folder has to be explicitly specified
    _app.template_folder = TEMPLATE_FOLDER
    test_client = _app.test_client()
    with _app.app_context():
        db.app = _app
        db.init_app(_app)
        db.create_all()
    return test_client


def _create_active_account(client, email: str, password: str):
    with mock.patch("passzero.email.send_email") as m1:
        assert isinstance(email, str)
        assert isinstance(password, str)
        # signup, etc etc
        # TODO for some reason can't mock out send_confirmation_email so mocking this instead
        m1.return_value = True
        api.signup(client, email, password, check_status=True)
        # get the token from calls
        token = m1.call_args[0][2].split("?")[1].replace("token=", "")
        # link = m1.call_args[0][2][m1.call_args[0][2].index("http://"):]
        # activate
        api.activate_account(client, token, check_status=True)
        # login
        api.login(client, email, password, check_status=True)


def _create_entry(client) -> int:
    token = api.get_csrf_token(client)
    entry = {
        "account": "foo",
        "username": "bar",
        "password": "foobar",
        "extra": "some xtra",
        "has_2fa": True
    }
    return api.create_entry(client, entry, token, check_status=True)


def _create_document(client) -> int:
    token = api.get_csrf_token(client)
    doc_params = {
        "name": "test document",
        "document": (BytesIO(b"hello world\n"), "hello_world.txt"),
        "mimetype": "text/plain"
    }
    return api.post_document(client, doc_params, token, check_status=True)

# ----- check pages that don't require login


def test_landing_template(test_client):
    r = test_client.get("/", follow_redirects=True)
    # only print on error
    print(r.data)
    assert r.status_code == 200


def test_login_template(test_client):
    r = test_client.get("/login", follow_redirects=True)
    print(r.data)
    assert r.status_code == 200


def test_signup_template(test_client):
    r = test_client.get("/signup", follow_redirects=True)
    print(r.data)
    assert r.status_code == 200


def test_about_template(test_client):
    r = test_client.get("/about", follow_redirects=True)
    assert r.status_code == 200


def test_version_template(test_client):
    r = test_client.get("/version", follow_redirects=True)
    assert r.status_code == 200


def test_recover_template(test_client):
    r = test_client.get("/recover", follow_redirects=True)
    assert r.status_code == 200


def test_post_account_delete_no_login(test_client):
    r = test_client.get("/post_account_delete", follow_redirects=True)
    assert r.status_code == 200


def test_post_confirm_signup_no_login(test_client):
    r = test_client.get("/signup/post_confirm", follow_redirects=True)
    assert r.status_code == 200

# ---- check redirect methods when pre-conditions not met -----


def test_post_login_no_login(test_client):
    r = test_client.get("/done_login", follow_redirects=True)
    # only print on error
    print(r.data)
    assert r.status_code == 401


def test_post_delete_no_login(test_client):
    r = test_client.get("/entries/post_delete/foo", follow_redirects=True)
    # only print on error
    print(r.data)
    assert r.status_code == 401


def test_post_update_no_login(test_client):
    r = test_client.get("/entries/done_edit/foo", follow_redirects=True)
    # only print on error
    print(r.data)
    assert r.status_code == 401


def test_post_create_no_login(test_client):
    r = test_client.get("/entries/done_new/foo", follow_redirects=True)
    # only print on error
    print(r.data)
    assert r.status_code == 401


def test_post_export_no_login(test_client):
    r = test_client.get("/advanced/done_export", follow_redirects=True)
    # only print on error
    print(r.data)
    assert r.status_code == 401

# ------ check API methods when conditions not met ------------


def test_export_no_login(test_client):
    r = test_client.get("/advanced/export", follow_redirects=True)
    # only print on error
    print(r.data)
    assert r.status_code == 401

# ------- check pages that require login to make sure they always redirect back to login page


def test_edit_entry_no_login(test_client):
    with test_client as c:
        response = c.get("/edit/1", follow_redirects=True)
        print(response.data)
        assert flask.request.path == flask.url_for("main_routes.login")


def test_new_entry_no_login(test_client):
    with test_client as c:
        response = c.get("/entries/new", follow_redirects=True)
        print(response.data)
        assert flask.request.path == flask.url_for("main_routes.login")


def test_view_entries_no_login(test_client):
    with test_client as c:
        response = c.get("/entries", follow_redirects=True)
        print(response.data)
        assert flask.request.path == flask.url_for("main_routes.login")


def test_view_links_no_login(test_client):
    with test_client as c:
        response = c.get("/links", follow_redirects=True)
        print(response.data)
        assert flask.request.path == flask.url_for("main_routes.login")


def test_new_link_no_login(test_client):
    with test_client as c:
        response = c.get("/links/new", follow_redirects=True)
        print(response.data)
        assert flask.request.path == flask.url_for("main_routes.login")


def test_edit_link_no_login(test_client):
    with test_client as c:
        response = c.get("/links/1", follow_redirects=True)
        print(response.data)
        assert flask.request.path == flask.url_for("main_routes.login")


def test_view_docs_no_login(test_client):
    with test_client as c:
        response = c.get("/docs", follow_redirects=True)
        print(response.data)
        assert flask.request.path == flask.url_for("main_routes.login")


def test_new_doc_no_login(test_client):
    with test_client as c:
        response = c.get("/docs/new", follow_redirects=True)
        print(response.data)
        assert flask.request.path == flask.url_for("main_routes.login")


def test_edit_doc_no_login(test_client):
    with test_client as c:
        response = c.get("/docs/1/edit", follow_redirects=True)
        print(response.data)
        assert flask.request.path == flask.url_for("main_routes.login")


def test_view_decrypted_doc_no_login(test_client):
    with test_client as c:
        response = c.get("/docs/1/view", follow_redirects=True)
        print(response.data)
        assert flask.request.path == flask.url_for("main_routes.login")


def test_password_strength_no_login(test_client):
    with test_client as c:
        response = c.get("/entries/strength", follow_redirects=True)
        print(response.data)
        assert flask.request.path == flask.url_for("main_routes.login")


def test_entry_2fa_no_login(test_client):
    with test_client as c:
        response = c.get("/entries/2fa", follow_redirects=True)
        print(response.data)
        assert flask.request.path == flask.url_for("main_routes.login")


def test_advanced_no_login(test_client):
    with test_client as c:
        response = c.get("/advanced", follow_redirects=True)
        print(response.data)
        assert flask.request.path == flask.url_for("main_routes.login")


def test_profile_no_login(test_client):
    with test_client as c:
        response = c.get("/profile", follow_redirects=True)
        print(response.data)
        assert flask.request.path == flask.url_for("main_routes.login")


def test_logout_no_login(test_client):
    with test_client as c:
        response = c.get("/logout", follow_redirects=True)
        print(response.data)
        assert flask.request.path == flask.url_for("main_routes.login")


def test_signup_no_signup(test_client):
    # just make sure everything is OK
    response = test_client.get("/done_signup/foo", follow_redirects=True)
    print(response.data)
    assert response.status_code == 200


def test_confirm_signup_no_token(test_client):
    """
    This method expects a token.
    Check what happens if no token is supplied
    Just make sure we don't error
    """
    response = test_client.get("/signup/confirm", follow_redirects=True)
    print(response.data)
    assert response.status_code == 200


def test_confirm_signup_invalid_token(test_client):
    """
    This method expects a token.
    Check what happens if the wrong token is supplied
    Just make sure we don't error
    """
    response = test_client.get("/signup/confirm?token=foo", follow_redirects=True)
    print(response.data)
    assert response.status_code == 200


def test_confirm_recover_no_token(test_client):
    """
    This method expects a token.
    Check what happens if no token is supplied
    Just make sure we don't error
    """
    # just make sure everything is OK
    response = test_client.get("/recover/confirm", follow_redirects=True)
    print(response.data)
    assert response.status_code == 200


def test_confirm_recover_invalid_token(test_client):
    """
    This method expects a token.
    Check what happens if the wrong token is supplied
    Just make sure we don't error
    """
    response = test_client.get("/recover/confirm?token=foo", follow_redirects=True)
    print(response.data)
    assert response.status_code == 200

# ---- test pages that do require login - (auth or abort) ------------


def test_done_login_with_login(test_client):
    with test_client as c:
        _create_active_account(c, DEFAULT_EMAIL, DEFAULT_PASSWORD)
        response = c.get("/done_login", follow_redirects=True)
        assert response.status_code == 200


def test_done_edit_with_login(test_client):
    with test_client as c:
        _create_active_account(c, DEFAULT_EMAIL, DEFAULT_PASSWORD)
        response = c.get("/entries/done_edit/foo", follow_redirects=True)
        assert response.status_code == 200


def test_done_new_with_login(test_client):
    with test_client as c:
        _create_active_account(c, DEFAULT_EMAIL, DEFAULT_PASSWORD)
        response = c.get("/entries/done_new/foo", follow_redirects=True)
        assert response.status_code == 200


def test_done_login_post_delete(test_client):
    with test_client as c:
        _create_active_account(c, DEFAULT_EMAIL, DEFAULT_PASSWORD)
        response = c.get("/entries/post_delete/foo", follow_redirects=True)
        assert response.status_code == 200


def test_done_export_with_login(test_client):
    with test_client as c:
        _create_active_account(c, DEFAULT_EMAIL, DEFAULT_PASSWORD)
        response = c.get("/advanced/done_export", follow_redirects=True)
        assert response.status_code == 200


# ----- test pages that do require login - ( auth_or_redirect_login ) -------
def test_root_with_login(test_client):
    with test_client as c:
        _create_active_account(c, DEFAULT_EMAIL, DEFAULT_PASSWORD)
        response = c.get("/", follow_redirects=True)
        assert response.status_code == 200
        assert flask.request.path == flask.url_for("main_routes.view_entries")


def test_view_entries_with_login(test_client):
    with test_client as c:
        _create_active_account(c, DEFAULT_EMAIL, DEFAULT_PASSWORD)
        response = c.get("/entries", follow_redirects=True)
        assert response.status_code == 200
        assert flask.request.path == flask.url_for("main_routes.view_entries")


def test_new_entry_view_with_login(test_client):
    with test_client as c:
        _create_active_account(c, DEFAULT_EMAIL, DEFAULT_PASSWORD)
        response = c.get("/entries/new", follow_redirects=True)
        assert response.status_code == 200
        assert flask.request.path == flask.url_for("main_routes.new_entry_view")


def test_view_links_with_login(test_client):
    with test_client as c:
        _create_active_account(c, DEFAULT_EMAIL, DEFAULT_PASSWORD)
        response = c.get("/links", follow_redirects=True)
        assert response.status_code == 200
        assert flask.request.path == flask.url_for("main_routes.view_links")


def test_new_link_view_with_login(test_client):
    with test_client as c:
        _create_active_account(c, DEFAULT_EMAIL, DEFAULT_PASSWORD)
        response = c.get("/links/new", follow_redirects=True)
        assert response.status_code == 200
        assert flask.request.path == flask.url_for("main_routes.new_link_view")


def test_edit_link_no_link_with_login(test_client):
    with test_client as c:
        _create_active_account(c, DEFAULT_EMAIL, DEFAULT_PASSWORD)
        response = c.get("/links/1", follow_redirects=True)
        assert response.status_code == 200
        # redirect to view links
        assert flask.request.path == flask.url_for("main_routes.view_links")


def test_view_docs_with_login(test_client):
    with test_client as c:
        _create_active_account(c, DEFAULT_EMAIL, DEFAULT_PASSWORD)
        response = c.get("/docs", follow_redirects=True)
        assert response.status_code == 200
        assert flask.request.path == flask.url_for("main_routes.view_docs")


def test_new_doc_view_with_login(test_client):
    with test_client as c:
        _create_active_account(c, DEFAULT_EMAIL, DEFAULT_PASSWORD)
        response = c.get("/docs/new", follow_redirects=True)
        assert response.status_code == 200
        assert flask.request.path == flask.url_for("main_routes.new_doc_view")


def test_view_decrypted_doc_no_doc_with_login(test_client):
    with test_client as c:
        _create_active_account(c, DEFAULT_EMAIL, DEFAULT_PASSWORD)
        response = c.get("/docs/1/view", follow_redirects=True)
        assert response.status_code == 200
        # redirect to view docs
        assert flask.request.path == flask.url_for("main_routes.view_docs")


def test_view_decrypted_doc_with_login(test_client):
    with test_client as c:
        _create_active_account(c, DEFAULT_EMAIL, DEFAULT_PASSWORD)
        document_id = _create_document(c)
        response = c.get(f"/docs/{document_id}/view", follow_redirects=True)
        assert response.status_code == 200
        assert flask.request.path == flask.url_for(
            "main_routes.view_decrypted_doc",
            document_id=document_id
        )


def test_edit_doc_no_doc_with_login(test_client):
    with test_client as c:
        _create_active_account(c, DEFAULT_EMAIL, DEFAULT_PASSWORD)
        response = c.get("/docs/1/edit", follow_redirects=True)
        assert response.status_code == 200
        # redirect to view docs
        assert flask.request.path == flask.url_for("main_routes.view_docs")


def test_edit_doc_with_login(test_client):
    with test_client as c:
        _create_active_account(c, DEFAULT_EMAIL, DEFAULT_PASSWORD)
        document_id = _create_document(c)
        response = c.get(f"/docs/{document_id}/edit", follow_redirects=True)
        assert response.status_code == 200
        # redirect to view docs
        assert flask.request.path == flask.url_for(
            "main_routes.edit_doc",
            document_id=document_id
        )


def test_edit_entry_view_with_login_invalid_entry(test_client):
    with test_client as c:
        _create_active_account(c, DEFAULT_EMAIL, DEFAULT_PASSWORD)
        response = c.get("/edit/1", follow_redirects=True)
        assert response.status_code == 200
        assert flask.request.path != flask.url_for("main_routes.login")


def test_strength_view_with_login(test_client):
    with test_client as c:
        _create_active_account(c, DEFAULT_EMAIL, DEFAULT_PASSWORD)
        response = c.get("/entries/strength", follow_redirects=True)
        assert response.status_code == 200
        assert flask.request.path != flask.url_for("main_routes.login")


def test_2fa_view_with_login_no_entries(test_client):
    with test_client as c:
        _create_active_account(c, DEFAULT_EMAIL, DEFAULT_PASSWORD)
        response = c.get("/entries/2fa", follow_redirects=True)
        assert response.status_code == 200
        assert flask.request.path != flask.url_for("main_routes.login")


def test_2fa_view_with_login_and_entries(test_client):
    with test_client as c:
        _create_active_account(c, DEFAULT_EMAIL, DEFAULT_PASSWORD)
        _create_entry(c)
        response = c.get("/entries/2fa", follow_redirects=True)
        assert response.status_code == 200
        assert flask.request.path != flask.url_for("main_routes.login")


def test_advanced_view_with_login(test_client):
    with test_client as c:
        _create_active_account(c, DEFAULT_EMAIL, DEFAULT_PASSWORD)
        response = c.get("/advanced", follow_redirects=True)
        assert response.status_code == 200
        assert flask.request.path != flask.url_for("main_routes.login")


def test_profile_view_with_login(test_client):
    with test_client as c:
        _create_active_account(c, DEFAULT_EMAIL, DEFAULT_PASSWORD)
        response = c.get("/profile", follow_redirects=True)
        assert response.status_code == 200
        assert flask.request.path != flask.url_for("main_routes.login")


def test_edit_entry_with_login(test_client):
    with test_client as c:
        _create_active_account(c, DEFAULT_EMAIL, DEFAULT_PASSWORD)
        entry_id = _create_entry(c)
        response = c.get("/edit/%d" % entry_id, follow_redirects=True)
        assert response.status_code == 200
        assert flask.request.path != flask.url_for("main_routes.login")


def test_recover_account_confirm(test_client):
    with mock.patch("passzero.email.send_email") as m1:
        m1.return_value = True
        with test_client as c:
            _create_active_account(c, DEFAULT_EMAIL, DEFAULT_PASSWORD)
            csrf_token = api.get_csrf_token(c)
            api.recover_account(c, DEFAULT_EMAIL, csrf_token)
            # NOTE for whatever reason cannot patch send_recovery_email...
            recovery_token = m1.call_args[0][2].split("token=")[1]
            response = c.get("/recover/confirm?token=%s" % recovery_token,
                             follow_redirects=True)
            assert response.status_code == 200
            assert flask.request.path == flask.url_for("main_routes.recover_account_confirm")


def test_signup_confirm(test_client):
    with mock.patch("passzero.email.send_email") as m1:
        m1.return_value = True
        with test_client as c:
            api.signup(c, DEFAULT_EMAIL, DEFAULT_PASSWORD, check_status=True)
            # NOTE for whatever reason cannot patch send_recovery_email...
            recovery_token = m1.call_args[0][2].split("token=")[1]
            response = c.get("/signup/confirm?token=%s" % recovery_token,
                             follow_redirects=True)
            assert response.status_code == 200


# ----------- other login stuff -----------
def test_logout_with_login(test_client):
    with test_client as c:
        _create_active_account(c, DEFAULT_EMAIL, DEFAULT_PASSWORD)
        response = c.get("/logout", follow_redirects=True)
        assert response.status_code == 200
