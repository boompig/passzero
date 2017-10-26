"""
This file contains methods that spell out the API for documents.
Supports basic CRUD over documents
"""

import logging

from flask import Blueprint, escape, session
from sqlalchemy.orm.exc import NoResultFound

from . import backend
from .api_utils import (json_error, json_internal_error, json_success,
                        requires_csrf_check, requires_json_auth,
                        requires_json_form_validation, write_json)
from .backend import ServerError, FileTooBigException
from .forms import NewDocumentForm
from .models import EncryptedDocument, db

docs_api = Blueprint("docs_api", __name__)


@docs_api.route("/api/v1/docs", methods=["GET"])
@requires_json_auth
def get_docs_api():
    """Retrieve all saved documents for the logged-in user
    The document contents will be encrypted.

    Arguments:
        none

    Response:
        on success:
            ```
            [doc-1, doc-2, ... doc-n]
            ```
            
            a document's object looks like this:
            ```
            {
                "id": number,
                "name": string,
                "document": binary
            }
            ```

            The contents will be encrypted

        on error:
            ```
            { "status": "error", "msg": string }
            ```

    Status codes:
        - 200: success
        - 401: user is not logged in
    """
    docs = db.session.query(EncryptedDocument).filter_by(user_id=session["user_id"]).all()
    rval = [doc.to_json() for doc in docs]
    return write_json(200, rval)


@docs_api.route("/api/v1/docs/<int:doc_id>", methods=["GET"])
@requires_json_auth
def decrypt_doc_api(doc_id):
    """
    Decrypt the specified document

    Arguments:
        none

    Response:
        on success:
        
        ```
        {
            "name": string,
            "document": string (base64-encoded binary)
        }

        ```
        on error:
            ```
            { "status": "error", "msg": string }
            ```

    Status codes:
        - 200: success
        - 400: document does not exist or does not belong to logged-in user
        - 401: user is not logged in
    """
    try:
        enc_doc = db.session.query(EncryptedDocument).\
            filter_by(id=doc_id, user_id=session["user_id"]).one()
        dec_doc = enc_doc.decrypt(session["password"])
        data = dec_doc.to_json()
        code = 200
    except NoResultFound:
        code, data = json_error(400,
            "Document ID does not correspond to the document" + \
            "or the document does not belong to you")
    return write_json(code, data)


@docs_api.route("/api/v1/docs", methods=["POST"])
@requires_json_auth
@requires_csrf_check
@requires_json_form_validation(NewDocumentForm)
def create_doc_api(form_data):
    """Upload a new document for the logged-in user

    Arguments:
        - name: string (required)
        - document: file (required)

    Response:
        on success:
            ```
            { "document_id": number }
            ```
        on error:
            ```
            { "status": "error", "msg": string }
            ```

    Status codes:
        - 200: success
        - 400: various input validation errors, also if file is too big
        - 401: not authenticated
        - 403: CSRF check failed
    """
    try:
        encrypted_file = backend.encrypt_document(
            db.session,
            session["user_id"],
            session["password"],
            form_data["name"],
            form_data["document"]
        )
        code = 200
        data = {"document_id": encrypted_file.id}
    except FileTooBigException as e:
        code, data = json_error(400, str(e))
    return write_json(code, data)



@docs_api.route("/api/v1/docs/<int:doc_id>", methods=["PATCH", "POST"])
@requires_json_auth
@requires_csrf_check
@requires_json_form_validation(NewDocumentForm)
def edit_doc_api(request_data, doc_id):
    """Edit the existing document or its metadata with the given ID.

    Arguments:
        - name: string (required)
        - document: file (required)

    Response:
        ```
        { "status": ("success" | "error"), "msg": string }
        ```

    Status codes:
        - 200: success
        - 400: various input validation errors, also if file is too big, or document does not belong to you
        - 401: not authenticated
        - 403: CSRF check failed
    """
    code = 200
    data = {}
    try:
        backend.edit_document(
            db.session,
            session["user_id"],
            session["password"],
            doc_id,
            request_data["name"],
            request_data["document"]
        )
        code, data = json_success(
            "successfully edited document %s" % escape(request_data["name"])
        )
    except NoResultFound:
        code, data = json_error(400, "no such document")
    except AssertionError as e:
        code, data = json_error(400, "the given document does not belong to you")
    except FileTooBigException as e:
        code, data = json_error(400, str(e))
    except ServerError as e:
        logging.error(e)
        code, data = json_internal_error("there was an internal server error. admin has been notified.")
    return write_json(code, data)


@docs_api.route("/api/v1/docs/<int:doc_id>", methods=["DELETE"])
@requires_json_auth
@requires_csrf_check
def delete_doc_api(doc_id):
    """Delete the document with the given ID.

    Arguments:
        none

    Response:
        ```
        { "status": "success"|"error", "msg": string }
        ```

    Status codes:
        - 200: success
        - 400: document does not exist or does not belong to logged-in user
        - 401: not authenticated
        - 403: CSRF check failed
    """
    try:
        enc_doc = db.session.query(EncryptedDocument).filter_by(id=doc_id).one()
        assert enc_doc.user_id == session['user_id']
        db.session.delete(enc_doc)
        db.session.commit()
        code, data = json_success("successfully deleted document with ID {}".format(
            doc_id))
    except NoResultFound:
        code, data = json_error(400, "no such document")
    except AssertionError:
        code, data = json_error(400, "the given document does not belong to you")
    return write_json(code, data)


@docs_api.route("/api/v1/docs/space", methods=["GET"])
@requires_json_auth
def get_docs_space_utilization():
    """
    Get the space utilization for the current logged-in user. This is just for documents.

    Response:
        on success:
        ```
        {
            "num_docs": number,
            "space_used": number,
            "space_remaining": number
        }
        ```

        on error:
        ```
        { "status": "error", "msg": string }
        ```

    Status codes:
        - 200: success
        - 401: not authenticated
    """
    data = backend.get_docs_space_utilization(db.session, session["user_id"])
    return write_json(200, data)

