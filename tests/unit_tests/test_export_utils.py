import csv
import os

from io import StringIO

import pytest
from passzero import backend, export_utils
from passzero.app_factory import create_app
from passzero.models import ApiToken, Entry, Service, User
from passzero.models import db as _db


DEFAULT_EMAIL = "sample@fake.com"
DEFAULT_PASSWORD = "right_pass"
DB_FILENAME = "passzero.db"


@pytest.fixture(scope="module")
def app(request):
    """Provide the fixture for the duration of the test, then tear it down"""
    # remove previous database if present
    if os.path.exists(DB_FILENAME):
        os.remove(DB_FILENAME)

    settings_override = {
        "SQLALCHEMY_DATABASE_URI": f"sqlite:///{DB_FILENAME}"
    }

    app = create_app(__name__, settings_override)
    ctx = app.app_context()
    ctx.push()

    def teardown():
        ctx.pop()

    request.addfinalizer(teardown)
    return app


@pytest.fixture(scope="module")
def db(app, request):
    if os.path.exists(DB_FILENAME):
        os.remove(DB_FILENAME)

    def teardown():
        _db.drop_all()
        if os.path.exists(DB_FILENAME):
            os.remove(DB_FILENAME)

    _db.app = app
    _db.create_all()

    request.addfinalizer(teardown)
    return _db


@pytest.fixture(scope="function")
def session(db, request):
    connection = db.engine.connect()
    transaction = connection.begin()

    options = dict(bind=connection)
    session = db.create_scoped_session(options=options)

    db.session = session

    def teardown():
        # I don't think this works completely
        transaction.rollback()

        # so have to manually clear users table
        session.query(User).delete()
        session.query(Entry).delete()
        session.query(Service).delete()
        session.query(ApiToken).delete()
        session.commit()

        connection.close()
        session.remove()

    request.addfinalizer(teardown)
    return session


def _assert_entries_equal(e1, e2):
    entry_fields = ["account", "username", "password", "extra"]
    for field in entry_fields:
        assert field in e1
        assert field in e2
        assert e1[field] == e2[field]


def test_export_decrypted_entries(session):
    entries_in = [
        {
            "account": "apple",
            "username": "hello@apple.com",
            "password": "worldApple7$!@#!",
            "extra": """
            this is a multi-line extra field
            lots of interesting stuff here
            """,
            "has_2fa": True
        },
        {
            "account": "gmail",
            "username": "hello@google.com",
            "password": "worldGoogle77",
            "extra": None,
            "has_2fa": False
        },
    ]
    user = backend.create_inactive_user(
        session,
        DEFAULT_EMAIL,
        DEFAULT_PASSWORD
    )
    backend.activate_account(session, user)
    for dec_entry in entries_in:
        backend.insert_entry_for_user(
            session,
            dec_entry,
            user.id,
            DEFAULT_PASSWORD
        )
    service = Service(
        name="apple",
        link="apple.com"
    )
    session.add(service)
    session.commit()
    out = export_utils.export_decrypted_entries(
        session,
        user.id,
        DEFAULT_PASSWORD
    )
    assert isinstance(out, str)
    # csv
    buf = StringIO(out)
    reader = csv.DictReader(buf)
    entries_out = [row for row in reader]
    entries_out.sort(key=lambda row: row["name"])
    for e_out in entries_out:
        for key in export_utils.EXPORT_FIELDS:
            assert key in e_out
