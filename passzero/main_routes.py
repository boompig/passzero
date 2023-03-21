from functools import wraps

from flask import (Blueprint, abort, current_app, escape, flash, make_response,
                   redirect, render_template, request, session, url_for)
from sqlalchemy.orm.exc import NoResultFound

from passzero import export_utils
from passzero.api_utils import check_auth
from passzero.backend import (activate_account, decrypt_entries,
                              get_document_by_id, get_entries, get_link_by_id,
                              get_services_map, password_strength_scores)
from passzero.models import AuthToken, User, db

main_routes = Blueprint("main_routes", __name__)


def auth_or_redirect_login(function):
    """This is a decorator which does authentication for GET requests to templates.
    If not authenticated, return a redirect to the login screen.
    If authenticated, call the function."""
    @wraps(function)
    def inner(*args, **kwargs):
        if check_auth():
            return function(*args, **kwargs)
        else:
            return redirect(url_for("main_routes.login"))
    return inner


def auth_or_abort(function):
    """This is a decorator which does authentication for GET requests to templates.
    If not authenticated, show the 401 screen.
    If authenticated, call the function."""
    @wraps(function)
    def inner(*args, **kwargs):
        if check_auth():
            return function(*args, **kwargs)
        else:
            return abort(401)
    return inner


@main_routes.route("/", methods=["GET"])
def index():
    if check_auth():
        return redirect(url_for("main_routes.view_entries"))
    else:
        return render_template("landing.jinja2")


@main_routes.route("/done_login", methods=["GET"])
@auth_or_abort
def post_login():
    flash(f"Successfully logged in as {escape(session['email'])}")
    return redirect(url_for("main_routes.view_entries"))


@main_routes.route("/login", methods=["GET"])
def login():
    return render_template("login_existing.jinja2",
                           title="PassZero &middot; Login")


@main_routes.route("/logout", methods=["GET", "POST"])
def logout():
    if 'email' in session:
        session.pop("email")
    if 'password' in session:
        session.pop("password")
    if 'user_id' in session:
        session.pop("user_id")
    return redirect(url_for("main_routes.login"))


@main_routes.route("/post_account_delete", methods=["GET", "POST"])
def post_account_delete():
    flash("Account successfully deleted")
    return redirect(url_for("main_routes.logout"))


@main_routes.route("/done_signup/<email>", methods=["GET"])
def post_signup(email: str):
    flash("Successfully created account with email %s. A confirmation email was sent to this address." % escape(email))
    return redirect(url_for("main_routes.login"))


# --- BEGIN entries --- #
@main_routes.route("/entries/post_delete/<account_name>", methods=["GET"])
@auth_or_abort
def post_delete(account_name: str):
    flash(f"Successfully deleted account {escape(account_name)}")
    return redirect(url_for("main_routes.view_entries"))


@main_routes.route("/entries/new", methods=["GET"])
@auth_or_redirect_login
def new_entry_view():
    user = db.session.query(User).filter_by(id=session["user_id"]).one()
    user_prefs = {
        "default_random_password_length": user.default_random_password_length,
        "default_random_passphrase_length": user.default_random_passphrase_length
    }
    return render_template("new.jinja2", title="PassZero &middot; New Entry",
                           user_prefs=user_prefs, error=None)


@main_routes.route("/entries/done_edit/<account_name>")
@auth_or_abort
def post_edit(account_name):
    flash(f"Successfully changed entry for account {escape(account_name)}")
    return redirect(url_for("main_routes.view_entries"))


@main_routes.route("/entries/done_new/<account_name>", methods=["GET"])
@auth_or_abort
def post_create(account_name):
    flash(f"Successfully created entry for account {escape(account_name)}")
    return redirect(url_for("main_routes.view_entries"))


@main_routes.route("/entries", methods=["GET"])
@auth_or_redirect_login
def view_entries():
    return render_template("entries.jinja2")
# --- END entries --- #


# --- BEGIN links --- #
@main_routes.route("/links", methods=["GET"])
@auth_or_redirect_login
def view_links():
    return render_template("links/links.jinja2")


@main_routes.route("/links/new", methods=["GET"])
@auth_or_redirect_login
def new_link_view():
    return render_template("links/new-link.jinja2", title="PassZero &middot; New Link", link_id=-1)


@main_routes.route("/links/<int:link_id>", methods=["GET"])
@auth_or_redirect_login
def edit_link(link_id: int):
    user = db.session.query(User).filter_by(id=session["user_id"]).one()
    link = get_link_by_id(db.session, user.id, link_id)
    if link is None:
        flash("Error: no link with ID %d" % link_id, "error")
        return redirect(url_for("main_routes.view_links"))
    dec_link = link.decrypt(session["password"])
    return render_template("links/new-link.jinja2", title="PassZero &middot; Edit Link",
                           link_id=link_id,
                           service_name=dec_link.service_name,
                           link=dec_link.link)
# --- END links --- #


# --- BEGIN documents --- #
@main_routes.route("/docs", methods=["GET"])
@auth_or_redirect_login
def view_docs():
    return render_template("docs/docs.jinja2")


@main_routes.route("/docs/new", methods=["GET"])
@auth_or_redirect_login
def new_doc_view():
    return render_template("docs/new-doc.jinja2", title="PassZero &middot; New Document",
                           document_id=-1)


@main_routes.route("/docs/<int:document_id>/edit", methods=["GET"])
@auth_or_redirect_login
def edit_doc(document_id: int):
    # get the document
    user = db.session.query(User).filter_by(id=session["user_id"]).one()
    doc = get_document_by_id(db.session, user.id, document_id)
    if doc is None:
        flash(f"Error: no document with ID {document_id}", "error")
        return redirect(url_for("main_routes.view_docs"))
    return render_template("docs/new-doc.jinja2", title="PassZero &middot; New Document",
                           document_id=document_id)


@main_routes.route("/docs/<int:document_id>/view", methods=["GET"])
@auth_or_redirect_login
def view_decrypted_doc(document_id: int):
    user = db.session.query(User).filter_by(id=session["user_id"]).one()
    doc = get_document_by_id(db.session, user.id, document_id)
    if doc is None:
        flash(f"Error: no document with ID {document_id}", "error")
        return redirect(url_for("main_routes.view_docs"))
    dec_doc = doc.decrypt(session["password"])
    return render_template(
        "docs/view-doc.jinja2",
        title="PassZero &middot; View Document",
        document_id=document_id,
        document_mimetype=dec_doc.mimetype,
        document_name=dec_doc.name
    )

# --- END documents --- #


@main_routes.route("/signup", methods=["GET"])
def signup():
    return render_template("login_new.jinja2",
                           title="PassZero &middot; Register")


@main_routes.route("/signup/post_confirm")
def post_confirm_signup():
    flash("Successfully signed up! Login with your newly created account")
    return redirect(url_for("main_routes.login"))


@main_routes.route("/signup/confirm")
def confirm_signup():
    try:
        token = request.args["token"]
        token_obj = db.session.query(AuthToken).filter_by(token=token).one()
        if token_obj.is_expired():
            flash("Token has expired", "error")
            # delete old token from database
            db.session.delete(token_obj)
            db.session.commit()
            return redirect(url_for("main_routes.signup"))
        else:
            # token deleted when password changed
            db.session.delete(token_obj)
            user = db.session.query(User).filter_by(id=token_obj.user_id).one()
            activate_account(db.session, user)
            return redirect(url_for("main_routes.post_confirm_signup"))
    except NoResultFound:
        flash("Token is invalid", "error")
        return redirect(url_for("main_routes.signup"))
    except KeyError:
        flash("Token is mandatory", "error")
        return redirect(url_for("main_routes.signup"))


@main_routes.route("/advanced/export", methods=["GET"])
@auth_or_abort
def export_entries():
    export_contents = export_utils.export_decrypted_entries(
        db.session,
        session["user_id"],
        session["password"]
    )
    response = make_response(export_contents)
    response.headers["Content-Disposition"] = (
        "attachment; filename=%s" % current_app.config['DUMP_FILE']
    )
    return response


@main_routes.route("/advanced/done_export")
@auth_or_abort
def done_export():
    flash("database successfully dumped to file %s" % current_app.config['DUMP_FILE'])
    return redirect("/advanced")


@main_routes.route("/edit/<int:entry_id>", methods=["GET"])
@main_routes.route("/entries/<int:entry_id>", methods=["GET"])
@auth_or_redirect_login
def edit_entry(entry_id: int):
    user = db.session.query(User).filter_by(id=session["user_id"]).one()
    entries = get_entries(db.session, session["user_id"])
    my_entries = [e for e in entries if e.id == entry_id]
    if len(my_entries) == 0:
        flash("Error: no entry with ID %d" % entry_id, "error")
        return redirect(url_for("main_routes.view_entries"))
    else:
        fe = decrypt_entries(my_entries, session['password'])
        user_prefs = {
            "default_random_password_length": user.default_random_password_length,
            "default_random_passphrase_length": user.default_random_passphrase_length
        }
        return render_template(
            "new.jinja2",
            user_prefs=user_prefs,
            e_id=entry_id,
            entry=fe[0],
            error=None
        )


@main_routes.route("/entries/strength")
@auth_or_redirect_login
def password_strength():
    entries = get_entries(db.session, session["user_id"])
    dec_entries = decrypt_entries(entries, session["password"])
    entry_scores = password_strength_scores(session["email"], dec_entries)
    return render_template("password_strength.jinja2", entry_scores=entry_scores)


@main_routes.route("/entries/2fa")
@auth_or_redirect_login
def two_factor():
    entries = get_entries(db.session, session["user_id"])
    services_map = get_services_map(db.session)
    two_factor_map = {}
    for entry in entries:
        account = entry.account.lower()
        two_factor_map[entry.account] = {
            "service_has_2fa": services_map.get(account, {}).get("has_two_factor", False),
            "entry_has_2fa": entry.has_2fa,
            "entry_id": entry.id
        }
    return render_template("entries_2fa.jinja2", two_factor_map=two_factor_map)


@main_routes.route("/advanced")
@auth_or_redirect_login
def advanced():
    return render_template("advanced.jinja2")


@main_routes.route("/profile")
@auth_or_redirect_login
def profile():
    return render_template(
        "profile.jinja2",
        title="PassZero &middot; Profile",
    )


@main_routes.route("/recover")
def recover_password():
    return render_template("recover.jinja2")


@main_routes.route("/recover/confirm")
def recover_account_confirm():
    try:
        token = request.args['token']
        token_obj = db.session.query(AuthToken).filter_by(token=token).one()
        if token_obj.is_expired():
            flash("Token has expired", "error")
            # delete old token from database
            db.session.delete(token_obj)
            db.session.commit()
            return redirect(url_for("main_routes.recover_password"))
        else:
            # token deleted when password changed
            return render_template("recover.jinja2", confirm=True)
    except NoResultFound:
        flash("Token is invalid", "error")
        return redirect(url_for("main_routes.recover_password"))
    except KeyError:
        flash("Token is mandatory", "error")
        return redirect(url_for("main_routes.recover_password"))


@main_routes.route("/about")
def about():
    return render_template("about.jinja2")


@main_routes.route("/version")
def get_version():
    return current_app.config['BUILD_ID']
