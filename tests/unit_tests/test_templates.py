"""
This module will test whether the templates fetched can be rendered at all
"""

import logging
import os
from typing import Generator
from unittest import mock

import flask
import pytest
from flask.testing import FlaskClient
from flask_sqlalchemy import SQLAlchemy

from passzero import backend
from passzero.app_factory import create_app
from passzero.models import (ApiToken, AuthToken,
                             EncryptionKeys, Entry, Link, Service, User)
from passzero.models import db as _db
from tests.common import api

DEFAULT_EMAIL = "sample@fake.com"
DEFAULT_PASSWORD = "right_pass"
TEMPLATE_FOLDER = os.path.realpath(os.path.dirname(__file__) + "/../../templates")


@pytest.fixture(scope="module")
def flask_client_perm(request) -> FlaskClient:
    _app = create_app(__name__, {
        "SQLALCHEMY_DATABASE_URI": "sqlite://",
        "SQLALCHEMY_TRACK_MODIFICATIONS": False,
        "BUILD_ID": "test",
        "WTF_CSRF_ENABLED": False,
        "JSONIFY_PRETTYPRINT_REGULAR": False,
        "TESTING": True
    })
    _app.secret_key = "foo"

    # template folder has to be explicitly specified
    _app.template_folder = TEMPLATE_FOLDER
    logging.basicConfig(level=logging.DEBUG)

    test_client = _app.test_client()
    return test_client


@pytest.fixture(scope="module")
def db(request, flask_client_perm: FlaskClient) -> SQLAlchemy:
    assert flask_client_perm is not None
    print("creating all tables...")
    _db.create_all()

    def teardown():
        _db.drop_all()
    request.addfinalizer(teardown)
    return _db


@pytest.fixture(scope="function")
def flask_client(request, db, flask_client_perm: FlaskClient) -> FlaskClient:

    def teardown():
        # delete API token
        db.session.query(ApiToken).delete()
        # delete entries
        db.session.query(Entry).delete()
        # delete links
        db.session.query(Link).delete()
        # delete auth token
        db.session.query(AuthToken).delete()
        # delete user
        db.session.query(User).delete()
        # delete services
        db.session.query(Service).delete()
        # delete encryption key database
        db.session.query(EncryptionKeys).delete()
        db.session.commit()

    request.addfinalizer(teardown)
    return flask_client_perm


@pytest.fixture(scope="function")
def active_user(flask_client: FlaskClient, db: SQLAlchemy) -> Generator:
    """Create a default active user with email=`DEFAULT_EMAIL` and password=`DEFAULT_PASSWORD`"""
    user = backend.create_inactive_user(
        db_session=db.session,
        email=DEFAULT_EMAIL,
        password=DEFAULT_PASSWORD,
    )
    backend.activate_account(db.session, user)
    yield user

    # then delete that user
    db.session.delete(user)
    db.session.commit()


def _create_entry(_client: FlaskClient, _db: SQLAlchemy, _user: User) -> int:
    """NOTE: user must be logged in"""
    dec_entry = {
        "account": "foo",
        "username": "bar",
        "password": "foobar",
        "extra": "some xtra",
        "has_2fa": True
    }
    entry = backend.insert_entry_for_user(
        _db.session,
        dec_entry,
        _user.id,
        DEFAULT_PASSWORD,
    )
    return entry.id


# ----- check pages that don't require login


def test_landing_template(flask_client: FlaskClient):
    r = flask_client.get("/", follow_redirects=True)
    # only print on error
    print(r.data)
    assert r.status_code == 200


def test_login_template(flask_client: FlaskClient):
    r = flask_client.get("/login", follow_redirects=True)
    print(r.data)
    assert r.status_code == 200


def test_signup_template(flask_client: FlaskClient):
    r = flask_client.get("/signup", follow_redirects=True)
    print(r.data)
    assert r.status_code == 200


def test_about_template(flask_client: FlaskClient):
    r = flask_client.get("/about", follow_redirects=True)
    assert r.status_code == 200


def test_version_template(flask_client: FlaskClient):
    r = flask_client.get("/version", follow_redirects=True)
    assert r.status_code == 200


def test_recover_template(flask_client: FlaskClient):
    r = flask_client.get("/recover", follow_redirects=True)
    assert r.status_code == 200


def test_post_account_delete_no_login(flask_client: FlaskClient):
    r = flask_client.get("/post_account_delete", follow_redirects=True)
    assert r.status_code == 200


def test_post_confirm_signup_no_login(flask_client: FlaskClient):
    r = flask_client.get("/signup/post_confirm", follow_redirects=True)
    assert r.status_code == 200

# ---- check redirect methods when pre-conditions not met -----


def test_post_login_no_login(flask_client: FlaskClient):
    r = flask_client.get("/done_login", follow_redirects=True)
    # only print on error
    print(r.data)
    assert r.status_code == 401


def test_post_delete_no_login(flask_client: FlaskClient):
    r = flask_client.get("/entries/post_delete/foo", follow_redirects=True)
    # only print on error
    print(r.data)
    assert r.status_code == 401


def test_post_update_no_login(flask_client: FlaskClient):
    r = flask_client.get("/entries/done_edit/foo", follow_redirects=True)
    # only print on error
    print(r.data)
    assert r.status_code == 401


def test_post_create_no_login(flask_client: FlaskClient):
    r = flask_client.get("/entries/done_new/foo", follow_redirects=True)
    # only print on error
    print(r.data)
    assert r.status_code == 401


def test_post_export_no_login(flask_client: FlaskClient):
    r = flask_client.get("/advanced/done_export", follow_redirects=True)
    # only print on error
    print(r.data)
    assert r.status_code == 401

# ------ check API methods when conditions not met ------------


def test_export_no_login(flask_client: FlaskClient):
    r = flask_client.get("/advanced/export", follow_redirects=True)
    # only print on error
    print(r.data)
    assert r.status_code == 401

# ------- check pages that require login to make sure they always redirect back to login page


def test_edit_entry_no_login(flask_client: FlaskClient):
    with flask_client as c:
        response = c.get("/edit/1", follow_redirects=True)
        print(response.data)
        assert flask.request.path == flask.url_for("main_routes.login")


def test_new_entry_no_login(flask_client: FlaskClient):
    with flask_client as c:
        response = c.get("/entries/new", follow_redirects=True)
        print(response.data)
        assert flask.request.path == flask.url_for("main_routes.login")


def test_view_entries_no_login(flask_client: FlaskClient):
    with flask_client as c:
        response = c.get("/entries", follow_redirects=True)
        print(response.data)
        assert flask.request.path == flask.url_for("main_routes.login")


def test_view_links_no_login(flask_client: FlaskClient):
    with flask_client as c:
        response = c.get("/links", follow_redirects=True)
        print(response.data)
        assert flask.request.path == flask.url_for("main_routes.login")


def test_new_link_no_login(flask_client: FlaskClient):
    with flask_client as c:
        response = c.get("/links/new", follow_redirects=True)
        print(response.data)
        assert flask.request.path == flask.url_for("main_routes.login")


def test_edit_link_no_login(flask_client: FlaskClient):
    with flask_client as c:
        response = c.get("/links/1", follow_redirects=True)
        print(response.data)
        assert flask.request.path == flask.url_for("main_routes.login")


def test_password_strength_no_login(flask_client: FlaskClient):
    with flask_client as c:
        response = c.get("/entries/strength", follow_redirects=True)
        print(response.data)
        assert flask.request.path == flask.url_for("main_routes.login")


def test_entry_2fa_no_login(flask_client: FlaskClient):
    with flask_client as c:
        response = c.get("/entries/2fa", follow_redirects=True)
        print(response.data)
        assert flask.request.path == flask.url_for("main_routes.login")


def test_advanced_no_login(flask_client: FlaskClient):
    with flask_client as c:
        response = c.get("/advanced", follow_redirects=True)
        print(response.data)
        assert flask.request.path == flask.url_for("main_routes.login")


def test_profile_no_login(flask_client: FlaskClient):
    with flask_client as c:
        response = c.get("/profile", follow_redirects=True)
        print(response.data)
        assert flask.request.path == flask.url_for("main_routes.login")


def test_logout_no_login(flask_client: FlaskClient):
    with flask_client as c:
        response = c.get("/logout", follow_redirects=True)
        print(response.data)
        assert flask.request.path == flask.url_for("main_routes.login")


def test_signup_no_signup(flask_client: FlaskClient):
    # just make sure everything is OK
    response = flask_client.get("/done_signup/foo", follow_redirects=True)
    print(response.data)
    assert response.status_code == 200


def test_confirm_signup_no_token(flask_client: FlaskClient):
    """
    This method expects a token.
    Check what happens if no token is supplied
    Just make sure we don't error
    """
    response = flask_client.get("/signup/confirm", follow_redirects=True)
    print(response.data)
    assert response.status_code == 200


def test_confirm_signup_invalid_token(flask_client: FlaskClient):
    """
    This method expects a token.
    Check what happens if the wrong token is supplied
    Just make sure we don't error
    """
    response = flask_client.get("/signup/confirm?token=foo", follow_redirects=True)
    print(response.data)
    assert response.status_code == 200


def test_confirm_recover_no_token(flask_client: FlaskClient):
    """
    This method expects a token.
    Check what happens if no token is supplied
    Just make sure we don't error
    """
    # just make sure everything is OK
    response = flask_client.get("/recover/confirm", follow_redirects=True)
    print(response.data)
    assert response.status_code == 200


def test_confirm_recover_invalid_token(flask_client: FlaskClient):
    """
    This method expects a token.
    Check what happens if the wrong token is supplied
    Just make sure we don't error
    """
    response = flask_client.get("/recover/confirm?token=foo", follow_redirects=True)
    print(response.data)
    assert response.status_code == 200

# ---- test pages that do require login - (auth or abort) ------------


def test_done_login_with_login(flask_client: FlaskClient, active_user: User):
    with flask_client as c:
        assert active_user is not None
        api.login_v1(flask_client, DEFAULT_EMAIL, DEFAULT_PASSWORD, check_status=True)
        response = c.get("/done_login", follow_redirects=True)
        assert response.status_code == 200


def test_done_edit_with_login(flask_client: FlaskClient, active_user: User):
    with flask_client as c:
        assert active_user is not None
        api.login_v1(flask_client, DEFAULT_EMAIL, DEFAULT_PASSWORD, check_status=True)
        response = c.get("/entries/done_edit/foo", follow_redirects=True)
        assert response.status_code == 200


def test_done_new_with_login(flask_client: FlaskClient, active_user: User):
    with flask_client as c:
        assert active_user is not None
        api.login_v1(flask_client, DEFAULT_EMAIL, DEFAULT_PASSWORD, check_status=True)
        response = c.get("/entries/done_new/foo", follow_redirects=True)
        assert response.status_code == 200


def test_done_login_post_delete(flask_client: FlaskClient, active_user: User):
    with flask_client as c:
        assert active_user is not None
        api.login_v1(flask_client, DEFAULT_EMAIL, DEFAULT_PASSWORD, check_status=True)
        response = c.get("/entries/post_delete/foo", follow_redirects=True)
        assert response.status_code == 200


def test_done_export_with_login(flask_client: FlaskClient, active_user: User):
    with flask_client as c:
        assert active_user is not None
        api.login_v1(flask_client, DEFAULT_EMAIL, DEFAULT_PASSWORD, check_status=True)
        response = c.get("/advanced/done_export", follow_redirects=True)
        assert response.status_code == 200


# ----- test pages that do require login - ( auth_or_redirect_login ) -------
def test_root_with_login(flask_client: FlaskClient, active_user: User):
    with flask_client as c:
        assert active_user is not None
        api.login_v1(flask_client, DEFAULT_EMAIL, DEFAULT_PASSWORD, check_status=True)
        response = c.get("/", follow_redirects=True)
        assert response.status_code == 200
        assert flask.request.path == flask.url_for("main_routes.view_entries")


def test_view_entries_with_login(flask_client: FlaskClient, active_user: User):
    with flask_client as c:
        assert active_user is not None
        api.login_v1(flask_client, DEFAULT_EMAIL, DEFAULT_PASSWORD, check_status=True)
        response = c.get("/entries", follow_redirects=True)
        assert response.status_code == 200
        assert flask.request.path == flask.url_for("main_routes.view_entries")


def test_new_entry_view_with_login(flask_client: FlaskClient, active_user: User):
    with flask_client as c:
        assert active_user is not None
        api.login_v1(flask_client, DEFAULT_EMAIL, DEFAULT_PASSWORD, check_status=True)
        response = c.get("/entries/new", follow_redirects=True)
        assert response.status_code == 200
        assert flask.request.path == flask.url_for("main_routes.new_entry_view")


def test_view_links_with_login(flask_client: FlaskClient, active_user: User):
    with flask_client as c:
        assert active_user is not None
        api.login_v1(flask_client, DEFAULT_EMAIL, DEFAULT_PASSWORD, check_status=True)
        response = c.get("/links", follow_redirects=True)
        assert response.status_code == 200
        assert flask.request.path == flask.url_for("main_routes.view_links")


def test_new_link_view_with_login(flask_client: FlaskClient, active_user: User):
    with flask_client as c:
        assert active_user is not None
        api.login_v1(flask_client, DEFAULT_EMAIL, DEFAULT_PASSWORD, check_status=True)
        response = c.get("/links/new", follow_redirects=True)
        assert response.status_code == 200
        assert flask.request.path == flask.url_for("main_routes.new_link_view")


def test_edit_link_no_link_with_login(flask_client: FlaskClient, active_user: User):
    with flask_client as c:
        assert active_user is not None
        api.login_v1(flask_client, DEFAULT_EMAIL, DEFAULT_PASSWORD, check_status=True)
        response = c.get("/links/1", follow_redirects=True)
        assert response.status_code == 200
        # redirect to view links
        assert flask.request.path == flask.url_for("main_routes.view_links")


def test_edit_entry_view_with_login_invalid_entry(flask_client: FlaskClient, active_user: User):
    with flask_client as c:
        assert active_user is not None
        api.login_v1(flask_client, DEFAULT_EMAIL, DEFAULT_PASSWORD, check_status=True)
        response = c.get("/edit/1", follow_redirects=True)
        assert response.status_code == 200
        assert flask.request.path != flask.url_for("main_routes.login")


def test_strength_view_with_login(flask_client: FlaskClient, active_user: User):
    with flask_client as c:
        assert active_user is not None
        api.login_v1(flask_client, DEFAULT_EMAIL, DEFAULT_PASSWORD, check_status=True)
        response = c.get("/entries/strength", follow_redirects=True)
        assert response.status_code == 200
        assert flask.request.path != flask.url_for("main_routes.login")


def test_2fa_view_with_login_no_entries(flask_client: FlaskClient, active_user: User):
    with flask_client as c:
        assert active_user is not None
        api.login_v1(flask_client, DEFAULT_EMAIL, DEFAULT_PASSWORD, check_status=True)
        response = c.get("/entries/2fa", follow_redirects=True)
        assert response.status_code == 200
        assert flask.request.path != flask.url_for("main_routes.login")


def test_2fa_view_with_login_and_entries(flask_client: FlaskClient, db, active_user: User):
    with flask_client as c:
        assert active_user is not None
        api.login_v1(flask_client, DEFAULT_EMAIL, DEFAULT_PASSWORD, check_status=True)
        _create_entry(c, db, active_user)
        response = c.get("/entries/2fa", follow_redirects=True)
        print(flask.request.path)
        assert response.status_code == 200, response.status_code
        assert flask.request.path != flask.url_for("main_routes.login")


def test_advanced_view_with_login(flask_client: FlaskClient, active_user: User):
    with flask_client as c:
        assert active_user is not None
        api.login_v1(flask_client, DEFAULT_EMAIL, DEFAULT_PASSWORD, check_status=True)
        response = c.get("/advanced", follow_redirects=True)
        assert response.status_code == 200
        assert flask.request.path != flask.url_for("main_routes.login")


def test_profile_view_with_login(flask_client: FlaskClient, active_user: User):
    with flask_client as c:
        assert active_user is not None
        api.login_v1(flask_client, DEFAULT_EMAIL, DEFAULT_PASSWORD, check_status=True)
        response = c.get("/profile", follow_redirects=True)
        assert response.status_code == 200
        assert flask.request.path != flask.url_for("main_routes.login")


def test_edit_entry_with_login(flask_client: FlaskClient, db, active_user: User):
    with flask_client as c:
        assert active_user is not None
        api.login_v1(flask_client, DEFAULT_EMAIL, DEFAULT_PASSWORD, check_status=True)
        entry_id = _create_entry(c, db, active_user)
        response = c.get("/edit/%d" % entry_id, follow_redirects=True)
        assert response.status_code == 200
        assert flask.request.path != flask.url_for("main_routes.login")


def test_signup_confirm(flask_client: FlaskClient, db: SQLAlchemy):
    with mock.patch("passzero.email.send_email", return_value=True) as m1:
        # m1.return_value = True
        with flask_client as c:
            # an entirely new account (note that it is inactive)
            print("creating new account...")
            api.user_register_v3(flask_client, DEFAULT_EMAIL, DEFAULT_PASSWORD)
            m1.assert_called_once()
            # NOTE for whatever reason cannot patch send_recovery_email...
            activation_token = m1.call_args[0][2].split("token=")[1]
            response = c.get("/signup/confirm?token=%s" % activation_token,
                             follow_redirects=True)
            assert response.status_code == 200


# ----------- other login stuff -----------
def test_logout_with_login(flask_client: FlaskClient, active_user: User):
    with flask_client as c:
        response = c.get("/logout", follow_redirects=True)
        assert response.status_code == 200
