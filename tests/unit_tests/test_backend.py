import os

import nose
from mock import MagicMock
from nose.tools import assert_equal
from sqlalchemy import create_engine
from sqlalchemy.orm.exc import NoResultFound
from sqlalchemy.orm.session import sessionmaker

from passzero.backend import (create_inactive_user, decrypt_entries,
                              delete_account, delete_all_entries,
                              get_account_with_email, get_entries,
                              insert_entry_for_user)
from passzero.models import Entry, User

DB_FILENAME = "passzero.db"


def create_app():
    from server import app
    from passzero.models import db
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///%s' % DB_FILENAME
    db.init_app(app)
    with app.app_context():
        db.create_all()
    return app, db


def create_sqlite_session():
    engine = create_engine('sqlite:///%s' % DB_FILENAME)
    _, db = create_app()
    session = sessionmaker(bind=engine)()
    return session


def setup_module():
    # creates tables
    create_app()


def teardown_module():
    os.remove(DB_FILENAME)


def setup_function():
    pass


def teardown_function():
    session = create_sqlite_session()
    # clear database
    session.query(User).delete()
    session.query(Entry).delete()
    session.commit()


def test_create_inactive_user():
    session = create_sqlite_session()
    email = "fake@email.com"
    password = "pwd"
    u1 = create_inactive_user(session, email, password)
    assert u1.id is not None
    u2 = get_account_with_email(session, email)
    assert u1.id == u2.id


def test_delete_account():
    session = create_sqlite_session()
    email = "fake@email.com"
    user_key = "master"
    user = create_inactive_user(session, email, user_key)
    assert user.id is not None
    # add an entry to that account
    dec_entry_in = {
        "account": "a",
        "username": "u",
        "password": "p",
        "extra": "e"
    }
    insert_entry_for_user(session, dec_entry_in, user.id, user_key)
    delete_account(session, user)
    try:
        u2 = get_account_with_email(session, email)
        # only printed on error
        print(u2)
        assert False
    except NoResultFound:
        assert True


def test_insert_entry_for_user():
    session = create_sqlite_session()
    dec_entry_in = {
        "account": "a",
        "username": "u",
        "password": "p",
        "extra": "e"
    }
    user_key = "master key"
    insert_entry_for_user(session, dec_entry_in, 1, user_key)
    # make sure the entry is inserted
    enc_entries = get_entries(session, 1)
    assert len(enc_entries) == 1
    dec_entries = decrypt_entries(enc_entries, user_key)
    assert len(dec_entries) == 1
    for field in dec_entry_in:
        assert dec_entry_in[field] == dec_entries[0][field]


def test_delete_all_entries():
    session = create_sqlite_session()
    user_key = "master key"
    user = create_inactive_user(session, "fake@em.com",
        user_key)
    for i in range(10):
        dec_entry_in = {
            "account": "a-%d" % i,
            "username": "u",
            "password": "p",
            "extra": "e"
        }
        insert_entry_for_user(session, dec_entry_in,
                user.id, user_key)
    enc_entries = get_entries(session, user.id)
    assert len(enc_entries) == 10
    delete_all_entries(session, user)
    enc_entries = get_entries(session, user.id)
    assert len(enc_entries) == 0



def test_encrypt_decrypt_entries():
    pass
    # # create multiple entries for this user
    # dec_entry = {
        # "account": "test account",
        # "username": "test username",
        # "password": "test password",
        # "extra": "test extra"
    # }
    # user_key = "test master key"
    # entry = encrypt_entry(user_key, dec_entry)
    # assert isinstance(entry, Entry)
    # dec_entry_again = entry.decrypt(user_key)
    # fields = ["account", "username", "password", "extra"]
    # for field in fields:
        # assert_equal(dec_entry_again[field], dec_entry[field])
    # dec_entry = {
        # "account": "test account",
        # "username": "test username",
        # "password": "test password",
        # "extra": "test extra"
    # }
    # user_key = "test master key"
    # entry = encrypt_entry(user_key, dec_entry)
    # assert isinstance(entry, Entry)
    # dec_entry_again = entry.decrypt(user_key)
    # fields = ["account", "username", "password", "extra"]
    # for field in fields:
        # assert_equal(dec_entry_again[field], dec_entry[field])


def test_get_account_with_email():
    session = MagicMock()
    email = "fake_email"
    password = "fake password"
    created_user = create_inactive_user(session, email, password)
    assert isinstance(created_user, User)
    assert_equal(created_user.email, email)
    # TODO this is not a test, just makes sure that nothing crashes
    user = get_account_with_email(session, email)
    # print this out on error
    print(user)
    assert True


if __name__ == "__main__":
    nose.main()
