from __future__ import print_function

import base64
# import json
import logging
import os
import unittest

import mock
import six
from six import BytesIO

from passzero.app_factory import create_app
from passzero.models import db

from . import api

DEFAULT_EMAIL = u"sample@fake.com"
DEFAULT_PASSWORD = u"right_pass"


class PassZeroDocTester(unittest.TestCase):
    def setUp(self):
        logging.basicConfig(level=logging.DEBUG)
        _app = create_app(__name__, settings_override={
            "SQLALCHEMY_DATABASE_URI": "sqlite://",
            "SQLALCHEMY_TRACK_MODIFICATIONS": False,
            "BUILD_ID": "test",
            "WTF_CSRF_ENABLED": False,
            "JSONIFY_PRETTYPRINT_REGULAR": False,
            "TESTING": True,
        })
        self.app = _app.test_client()
        with _app.app_context():
            db.app = _app
            db.init_app(_app)
            db.create_all()

    def tearDown(self):
        db.drop_all()

    @mock.patch("passzero.email.send_email")
    def _create_active_account(self, email, password, m1):
        assert isinstance(email, six.text_type)
        assert isinstance(password, six.text_type)
        # signup, etc etc
        # TODO for some reason can't mock out send_confirmation_email so mocking this instead
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

    def __create_and_verify_text_doc(self):
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
        assert docs_after[0]["name"] == doc_params["name"]
        # decrypt the document
        doc = api.get_document(self.app, docs_after[0]["id"], check_status=True)
        assert base64.b64decode(doc["contents"]) == b"hello world\n"
        return docs_after[0]["id"]

    def __create_and_verify_binary_doc(self):
        with open("tests/unit_tests/data/Kutaisi-Mountain-Landscape-4K-Wallpaper.jpg", "rb") as fp:
            contents = fp.read()
        doc_params = {
            "name": "4K wallpaper",
            "document": (BytesIO(contents), "wallpaper.jpg")
        }
        upload_doc_token = api.get_csrf_token(self.app)
        api.post_document(self.app, doc_params, upload_doc_token, check_status=True)
        docs_after = api.get_documents(self.app, check_status=True)
        assert len(docs_after) == 1
        assert isinstance(docs_after[0]["id"], int)
        assert docs_after[0]["name"] == doc_params["name"]
        doc = api.get_document(self.app, docs_after[0]["id"], check_status=True)
        assert isinstance(contents, bytes)
        assert len(contents) > 0
        assert base64.b64decode(doc["contents"]) == contents
        return docs_after[0]["id"]

    def __verify_delete_doc(self, document_id):
        delete_token = api.get_csrf_token(self.app)
        api.delete_document(self.app, document_id, delete_token, check_status=True)
        docs_after_delete = api.get_documents(self.app, check_status=True)
        assert docs_after_delete == []

    def test_upload_and_get_doc_then_delete(self):
        self._create_active_account(DEFAULT_EMAIL, DEFAULT_PASSWORD)
        api.login(self.app, DEFAULT_EMAIL, DEFAULT_PASSWORD, check_status=True)
        document_id = self.__create_and_verify_text_doc()
        self.__verify_delete_doc(document_id)
        document_id = self.__create_and_verify_binary_doc()
        self.__verify_delete_doc(document_id)

    def test_no_such_doc(self):
        self._create_active_account(DEFAULT_EMAIL, DEFAULT_PASSWORD)
        api.login(self.app, DEFAULT_EMAIL, DEFAULT_PASSWORD, check_status=True)
        docs_before = api.get_documents(self.app, check_status=True)
        assert docs_before == []
        r = api.get_document(self.app, 1, check_status=False)
        assert r.status_code == 400
