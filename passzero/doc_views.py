from flask import Blueprint, escape, flash, redirect, render_template, url_for

from passzero.api_utils import auth_or_abort, check_auth

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


@doc_views.route("/docs/done_edit/<doc_name>")
@auth_or_abort
def done_doc_edit_redirect(doc_name):
    flash("Successfully changed document %s" % escape(doc_name))
    return redirect(url_for("doc_views.view_docs"))
