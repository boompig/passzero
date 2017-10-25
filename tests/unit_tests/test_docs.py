from __future__ import print_function

import binascii
import logging
import os
import unittest

import mock
from flask import Flask
from six import BytesIO

from passzero.api_v1 import api_v1
from passzero.docs_api import docs_api
from passzero.models import db

from . import api

app = Flask(__name__)
app.secret_key = 'foo'
app.register_blueprint(docs_api)
app.register_blueprint(api_v1)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite://"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config['WTF_CSRF_ENABLED'] = False

DEFAULT_EMAIL = "sample@fake.com"
DEFAULT_PASSWORD = "right_pass"


class PassZeroDocTester(unittest.TestCase):
    def setUp(self):
        logging.basicConfig(level=logging.DEBUG)
        self.app = app.test_client()
        db.app = app
        db.init_app(app)
        db.create_all()

    @mock.patch("passzero.email.send_email")
    def _create_active_account(self, email, password, m1):
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

    def test_no_docs(self):
        self._create_active_account(DEFAULT_EMAIL, "pass")
        api.login(self.app, DEFAULT_EMAIL, "pass", check_status=True)
        docs_before = api.get_docs(self.app, check_status=True)
        assert docs_before == []

    def test_upload_and_get_doc_then_delete(self):
        self._create_active_account(DEFAULT_EMAIL, "pass")
        api.login(self.app, DEFAULT_EMAIL, "pass", check_status=True)
        doc_params = {
            "name": "test document",
            "document": (BytesIO(b"hello world\n"), "hello_world.txt")
        }
        docs_before = api.get_docs(self.app, check_status=True)
        assert docs_before == []
        api.post_doc(self.app, doc_params, check_status=True)
        docs_after = api.get_docs(self.app, check_status=True)
        assert len(docs_after) == 1
        assert type(docs_after[0]["id"]) == int
        assert docs_after[0]["name"] == "test document"
        # decrypt the document
        doc = api.get_doc(self.app, docs_after[0]["id"], check_status=True)
        assert binascii.a2b_base64(doc["contents"]) == "hello world\n"
        api.delete_doc(self.app, docs_after[0]["id"], check_status=True)
        docs_after_delete = api.get_docs(self.app, check_status=True)
        assert docs_after_delete == []

    def test_get_doc_no_such_doc(self):
        self._create_active_account(DEFAULT_EMAIL, "pass")
        api.login(self.app, DEFAULT_EMAIL, "pass", check_status=True)
        docs_before = api.get_docs(self.app, check_status=True)
        assert docs_before == []
        r = api.get_doc(self.app, 1, check_status=False)
        assert r.status_code == 400

    def test_edit_doc(self):
        # create a random 0.5KB file
        contents = os.urandom(512)
        doc_params = {
            "name": "random stream",
            "document": (BytesIO(contents), "foo.bin")
        }
        self._create_active_account(DEFAULT_EMAIL, "pass")
        api.login(self.app, DEFAULT_EMAIL, "pass", check_status=True)
        doc_id = api.post_doc(self.app, doc_params, check_status=True)["document_id"]
        assert isinstance(doc_id, int)
        # get the document back
        doc = api.get_doc(self.app, doc_id, check_status=True)
        # make sure the content-type is set
        assert doc["content_type"] == "application/octet-stream"
        new_doc_params = {
            "name": "new name",
            "document": (BytesIO("foo\n"), "foo.txt")
        }
        api.edit_doc(self.app, doc_id, new_doc_params, check_status=True)
        new_doc = api.get_doc(self.app, doc_id, check_status=True)
        assert new_doc["name"] == new_doc_params["name"]
        assert binascii.a2b_base64(new_doc["contents"]) == "foo\n"
        assert new_doc["content_type"] == "text/plain"
        
    def test_edit_doc_no_such_doc(self):
        contents = os.urandom(512)
        doc_params = {
            "name": "random stream",
            "document": (BytesIO(contents), "foo.bin")
        }
        self._create_active_account(DEFAULT_EMAIL, "pass")
        api.login(self.app, DEFAULT_EMAIL, "pass", check_status=True)
        docs_before = api.get_docs(self.app, check_status=True)
        assert docs_before == []
        r = api.edit_doc(self.app, 1, doc_params, check_status=False)
        assert r.status_code == 400

    def test_edit_doc_not_yours(self):
        contents = os.urandom(512)
        doc_params = {
            "name": "random stream",
            "document": (BytesIO(contents), "foo.bin")
        }
        self._create_active_account("fake1@foo.com", "pass")
        self._create_active_account("fake2@foo.com", "pass")
        # first guy creates a document
        api.login(self.app, "fake1@foo.com", "pass", check_status=True)
        doc_id = api.post_doc(self.app, doc_params, check_status=True)["document_id"]
        assert isinstance(doc_id, int)
        api.logout(self.app)
        # second guy tries to edit document of first guy
        api.login(self.app, "fake2@foo.com", "pass", check_status=True)
        new_doc_params = {
            "name": "new name",
            "document": (BytesIO("foo\n"), "foo.txt")
        }
        r = api.edit_doc(self.app, doc_id, new_doc_params, check_status=False)
        assert r.status_code == 400

    def test_delete_doc_not_yours(self):
        contents = os.urandom(512)
        doc_params = {
            "name": "random stream",
            "document": (BytesIO(contents), "foo.bin")
        }
        self._create_active_account("fake1@foo.com", "pass")
        self._create_active_account("fake2@foo.com", "pass")
        # first guy creates a document
        api.login(self.app, "fake1@foo.com", "pass", check_status=True)
        doc_id = api.post_doc(self.app, doc_params, check_status=True)["document_id"]
        assert isinstance(doc_id, int)
        api.logout(self.app)
        # second guy tries to delete document of first guy
        api.login(self.app, "fake2@foo.com", "pass", check_status=True)
        r = api.delete_doc(self.app, doc_id, check_status=False)
        assert r.status_code == 400

    def test_delete_doc_no_such_doc(self):
        contents = os.urandom(512)
        doc_params = {
            "name": "random stream",
            "document": (BytesIO(contents), "foo.bin")
        }
        self._create_active_account(DEFAULT_EMAIL, DEFAULT_PASSWORD)
        api.login(self.app, DEFAULT_EMAIL, DEFAULT_PASSWORD, check_status=True)
        doc_id = api.post_doc(self.app, doc_params, check_status=True)["document_id"]
        assert isinstance(doc_id, int)
        r = api.delete_doc(self.app, doc_id + 1, check_status=False)
        assert r.status_code == 400
