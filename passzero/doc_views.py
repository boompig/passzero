from flask import Blueprint, render_template, redirect, url_for
from passzero.api_utils import check_auth

doc_views = Blueprint("doc_views", __name__)


@doc_views.route("/docs", methods=["GET"])
def view_docs():
    if not check_auth():
        return redirect(url_for("login"))
    return render_template("docs.html")


@doc_views.route("/docs/new", methods=["GET"])
def new_doc():
    if not check_auth():
        return redirect(url_for("login"))
    return render_template("new_doc.html")


@doc_views.route("/docs/<int:doc_id>", methods=["GET"])
def existing_doc(doc_id):
    if not check_auth():
        return redirect(url_for("login"))
    return render_template("new_doc.html", doc_id=doc_id)

