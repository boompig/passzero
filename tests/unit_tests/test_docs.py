from __future__ import print_function

# import json
import logging
import os
import unittest

import mock
import six
from flask import Flask
from six import BytesIO

from passzero.api_v1 import api_v1
from passzero.models import db

from . import api

app = Flask(__name__)
app.secret_key = 'foo'
app.register_blueprint(api_v1, prefix="")
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite://"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config['WTF_CSRF_ENABLED'] = False

DEFAULT_EMAIL = u"sample@fake.com"
DEFAULT_PASSWORD = u"right_pass"


class PassZeroDocTester(unittest.TestCase):
    def setUp(self):
        logging.basicConfig(level=logging.DEBUG)
        self.app = app.test_client()
        db.app = app
        db.init_app(app)
        db.create_all()

    @mock.patch("passzero.email.send_email")
    def _create_active_account(self, email, password, m1):
        assert isinstance(email, six.text_type)
        assert isinstance(password, six.text_type)
        # signup, etc etc
        #TODO for some reason can't mock out send_confirmation_email so mocking this instead
        m1.return_value = True
        r = api.signup(self.app, email, password)
        print(r.data)
        # only printed on error
        assert r.status_code == 200
        # get the token from calls
        token = m1.call_args[0][2].split("?")[1].replace("token=", "")
        # link = m1.call_args[0][2][m1.call_args[0][2].index("http://"):]
        # activate
        r = api.activate_account(self.app, token)
        print(r.data)
        assert r.status_code == 200
        # r = api.login(self.app, email, password)
        # print(r.data)
        # assert r.status_code == 200


    def create_test_doc(self):
        fname = "/tmp/foo.txt"
        if os.path.exists(fname):
            os.remove(fname)
        with open(fname, "w") as fp:
            fp.write("hello world\n")

    def test_no_docs(self):
        self._create_active_account(DEFAULT_EMAIL, DEFAULT_PASSWORD)
        api.login(self.app, DEFAULT_EMAIL, DEFAULT_PASSWORD, check_status=True)
        docs_before = api.get_documents(self.app, check_status=True)
        assert docs_before == []

    def test_upload_and_get_doc_then_delete(self):
        self._create_active_account(DEFAULT_EMAIL, DEFAULT_PASSWORD)
        api.login(self.app, DEFAULT_EMAIL, DEFAULT_PASSWORD, check_status=True)
        upload_doc_token = api.get_csrf_token(self.app)
        doc_params = {
            "name": "test document",
            "document": (BytesIO(b"hello world\n"), "hello_world.txt")
        }
        docs_before = api.get_documents(self.app, check_status=True)
        assert docs_before == []
        api.post_document(self.app, doc_params, upload_doc_token, check_status=True)
        docs_after = api.get_documents(self.app, check_status=True)
        assert len(docs_after) == 1
        assert type(docs_after[0]["id"]) == int
        assert docs_after[0]["name"] == "test document"
        # decrypt the document
        doc = api.get_document(self.app, docs_after[0]["id"], check_status=True)
        assert doc["contents"] == "hello world\n"
        delete_token = api.get_csrf_token(self.app)
        api.delete_document(self.app, docs_after[0]["id"], delete_token, check_status=True)
        docs_after_delete = api.get_documents(self.app, check_status=True)
        assert docs_after_delete == []

    def test_no_such_doc(self):
        self._create_active_account(DEFAULT_EMAIL, DEFAULT_PASSWORD)
        api.login(self.app, DEFAULT_EMAIL, DEFAULT_PASSWORD, check_status=True)
        docs_before = api.get_documents(self.app, check_status=True)
        assert docs_before == []
        r = api.get_document(self.app, 1, check_status=False)
        assert r.status_code == 400
