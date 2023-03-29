from functools import wraps

from flask import (Blueprint, abort, current_app, escape, flash, make_response,
                   redirect, render_template, request, session, url_for)
from sqlalchemy.orm.exc import NoResultFound

from passzero import export_utils
from passzero.api_utils import check_auth
from passzero.backend import (activate_account, decrypt_entries,
                              get_entries, get_link_by_id)
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
    return render_template(
        "login_existing.jinja2",
        title="PassZero &middot; Login"
    )


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
    # user_prefs are passed in this way to React
    return render_template(
        "new_entry.jinja2",
        title="PassZero &middot; New Entry",
        user_prefs=user_prefs,
        error=None
    )


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
    return render_template(
        "entries.jinja2",
        title="PassZero &middot; Entries"
    )

# --- END entries --- #


# --- BEGIN links --- #
@main_routes.route("/links", methods=["GET"])
@auth_or_redirect_login
def view_links():
    return render_template(
        "links/links.jinja2",
        title="PassZero &middot; Links"
    )


@main_routes.route("/links/new", methods=["GET"])
@auth_or_redirect_login
def new_link_view():
    return render_template(
        "links/new-link.jinja2",
        title="PassZero &middot; New Link",
        link_id=-1
    )


@main_routes.route("/links/<int:link_id>", methods=["GET"])
@auth_or_redirect_login
def edit_link(link_id: int):
    user = db.session.query(User).filter_by(id=session["user_id"]).one()
    link = get_link_by_id(db.session, user.id, link_id)
    if link is None:
        flash("Error: no link with ID %d" % link_id, "error")
        return redirect(url_for("main_routes.view_links"))
    dec_link = link.decrypt(session["password"])
    return render_template(
        "links/new-link.jinja2",
        title="PassZero &middot; Edit Link",
        link_id=link_id,
        service_name=dec_link.service_name,
        link=dec_link.link
    )
# --- END links --- #


@main_routes.route("/signup", methods=["GET"])
def signup():
    return render_template(
        "login_new.jinja2",
        title="PassZero &middot; Register"
    )


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
            "new_entry.jinja2",
            title="PassZero &middot; Edit Entry",
            user_prefs=user_prefs,
            e_id=entry_id,
            entry=fe[0],
            error=None
        )


@main_routes.route("/entries/strength")
@auth_or_redirect_login
def password_strength():
    return render_template(
        "entries_password_strength.jinja2",
        title="PassZero &middot; Password Strength Audit",
    )


@main_routes.route("/entries/2fa")
@auth_or_redirect_login
def two_factor():
    return render_template(
        "entries_two_factor.jinja2",
        title="PassZero &middot; Two Factor Audit",
    )


@main_routes.route("/advanced")
@auth_or_redirect_login
def advanced():
    return render_template(
        "advanced.jinja2",
        title="PassZero &middot; Advanced Features",
    )


@main_routes.route("/profile")
@auth_or_redirect_login
def profile():
    return render_template(
        "profile.jinja2",
        title="PassZero &middot; Profile",
    )


@main_routes.route("/recover")
def recover_password():
    return render_template(
        "recover.jinja2",
        title="PassZero &middot; Recover Account",
    )


@main_routes.route("/recover/confirm")
def recover_account_confirm():
    if "token" not in request.args:
        return "token is required"
    return render_template(
        "recover.jinja2",
        title="PassZero &middot; Confirm Recover Account",
    )


@main_routes.route("/about")
def about():
    return render_template(
        "about.jinja2",
        title="PassZero &middot; About"
    )


@main_routes.route("/version")
def get_version():
    return current_app.config['BUILD_ID']
