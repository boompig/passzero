import csv
import unittest
import logging

from six import StringIO
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from passzero import backend
from passzero.datastore_postgres import db_export
from passzero.my_env import DATABASE_URL

DEFAULT_EMAIL = u"sample@fake.com"
DEFAULT_MASTER_KEY = u"some long key 1&!@#$"

logging.basicConfig(level=logging.DEBUG)


class PassZeroApiTester(unittest.TestCase):
    def get_db_session(self):
        engine = create_engine(DATABASE_URL)
        Session = sessionmaker(bind=engine)
        return Session()

    def setUp(self):
        logging.debug("[test_export.setUp] Setting up...")
        session = self.get_db_session()
        user = backend.create_inactive_user(
            session, DEFAULT_EMAIL, DEFAULT_MASTER_KEY)
        backend.activate_account(
            session, user)

    def tearDown(self):
        logging.debug("[test_export.tearDown] Cleaning up...")
        session = self.get_db_session()
        user = backend.get_account_with_email(session, DEFAULT_EMAIL)
        backend.delete_account(session, user)
        logging.debug("[test_export.tearDown] Cleanup complete")

    def test_db_export_with_rows(self):
        session = self.get_db_session()
        user = backend.get_account_with_email(session, DEFAULT_EMAIL)
        expected_num_rows = 100
        # create rows
        for i in range(expected_num_rows):
            dec_entry = {
                "account": "fake account %d" % i,
                "username": "username %d" % i,
                "password": "password %d" % i,
                "extra": "extra field %d" % i,
                "has_2fa": True
            }
            backend.insert_entry_for_user(
                    session, dec_entry, user.id, DEFAULT_MASTER_KEY)
        result = db_export(session, user.id)
        # make sure the rows are all in valid CSV form
        num_rows = 0
        fp = StringIO(result)
        reader = csv.DictReader(fp)
        for row in reader:
            num_rows += 1
            assert "account" in row
            assert "username" in row
            assert "password" in row
            assert "extra" in row
        assert num_rows == expected_num_rows

    def test_db_export_invalid_user_id(self):
        """Make sure that this doesn't work for user ID that is not int
        This is a security check"""
        session = self.get_db_session()
        try:
            db_export(session, "foo")
        except Exception:
            assert True
        else:
            assert False
