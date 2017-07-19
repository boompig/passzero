import os

from flask import (Flask, escape, flash, make_response, redirect,
                   render_template, request, session, url_for)
from flask.ext.compress import Compress
from werkzeug.contrib.fixers import ProxyFix

import passzero.config as pz_config
from flask_sslify import SSLify
from passzero.api_utils import check_auth, generate_csrf_token
from passzero.api_v1 import api_v1
from passzero.api_v2 import api_v2
from passzero.backend import (activate_account, decrypt_entries, get_entries,
                              password_strength_scores, get_services_map)
from passzero.datastore_postgres import db_export
from passzero.models import AuthToken, User, db
from sqlalchemy.orm.exc import NoResultFound

if os.path.exists("passzero/my_env.py"):
    from passzero.my_env import setup_env
    setup_env()

compress = Compress()
app = Flask(__name__, static_url_path="")
compress.init_app(app)
app.config.from_object(pz_config)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ['DATABASE_URL']
app.config['DUMP_FILE'] = "passzero_dump.csv"
app.register_blueprint(api_v1)
app.register_blueprint(api_v2, prefix="/api/v2")

# define global callback for CSRF token"""
app.jinja_env.globals["csrf_token"] = generate_csrf_token

if 'FLASK_SECRET_KEY' in os.environ:
    app.secret_key = str(os.environ["FLASK_SECRET_KEY"])
    sslify = SSLify(app, permanent=True)
    DEBUG = False
else:
    if 'NO_SSL' not in os.environ:
        sslify = SSLify(app, permanent=True)
    app.secret_key = '64f5abcf8369e362c36a6220128de068'
    DEBUG = True

db.app = app
db.init_app(app)


@app.route("/", methods=["GET"])
def index():
    if check_auth():
        return redirect(url_for("view_entries"))
    else:
        return render_template("landing.html")


@app.route("/entries/post_delete/<account_name>", methods=["GET"])
def post_delete(account_name):
    flash("Successfully deleted account %s" % escape(account_name))
    return redirect(url_for("view_entries"))


@app.route("/done_login", methods=["GET"])
def post_login():
    flash("Successfully logged in as %s" % escape(session['email']))
    return redirect(url_for("view_entries"))


@app.route("/login", methods=["GET"])
def login():
    return render_template("login.html", login=True, error=None)


@app.route("/logout", methods=["GET", "POST"])
def logout():
    if 'email' in session:
        session.pop("email")
    if 'password' in session:
        session.pop("password")
    if 'user_id' in session:
        session.pop("user_id")
    return redirect(url_for("login"))


@app.route("/entries/new", methods=["GET"])
def new_entry_view():
    if not check_auth():
        return redirect(url_for("login"))
    user = db.session.query(User).filter_by(id=session["user_id"]).one()
    user_prefs = {
        "default_random_password_length": user.default_random_password_length,
        "default_random_passphrase_length": user.default_random_passphrase_length
    }
    return render_template("new.html", title="PassZero &middot; New Entry",
            user_prefs=user_prefs, error=None)


@app.route("/done_signup/<email>", methods=["GET"])
def post_signup(email):
    flash("Successfully created account with email %s. A confirmation email was sent to this address." % escape(email))
    return redirect(url_for("login"))


@app.route("/entries/done_edit/<account_name>")
def post_edit(account_name):
    flash("Successfully changed entry for account %s" % escape(account_name))
    return redirect(url_for("view_entries"))


@app.route("/entries/done_new/<account_name>")
def post_create(account_name):
    flash("Successfully created entry for account %s" % escape(account_name))
    return redirect(url_for("view_entries"))


@app.route("/view", methods=["GET"])
def view_entries():
    if not check_auth():
        #TODO flash some kind of error here
        return redirect(url_for("login"))
    return render_template("entries.html")


@app.route("/signup", methods=["GET"])
def signup():
    error = None
    #flash("Successfully created account with email %s" % request.form['email'])
    return render_template("login.html", login=False, error=error)


@app.route("/signup/post_confirm")
def post_confirm_signup():
    flash("Successfully signed up! Login with your newly created account")
    return redirect(url_for("login"))


@app.route("/signup/confirm")
def confirm_signup():
    try:
        token = request.args['token']
        token_obj = db.session.query(AuthToken).filter_by(token=token).one()
        if token_obj.is_expired():
            flash("Token has expired")
            # delete old token from database
            db.session.delete(token_obj)
            db.session.commit()
            return redirect(url_for("signup"))
        else:
            # token deleted when password changed
            db.session.delete(token_obj)
            user = db.session.query(User).filter_by(id=token_obj.user_id).one()
            activate_account(db.session, user)
            return redirect(url_for("post_confirm_signup"))
    except NoResultFound:
        flash("Token is invalid")
        return redirect(url_for("signup"))
    except KeyError:
        flash("Token is mandatory")
        return redirect(url_for("signup"))


@app.route("/advanced/export", methods=["GET"])
def export_entries():
    if not check_auth():
        #TODO
        return "unauthorized"
    export_contents = db_export(db.session, session['user_id'])
    if export_contents:
        response = make_response(export_contents)
        response.headers["Content-Disposition"] = ("attachment; filename=%s" %\
                app.config['DUMP_FILE'])
        return response
    else:
        return "failed to export table - internal error"


@app.route("/advanced/done_export")
def post_export():
    flash("database successfully dumped to file %s" % app.config['DUMP_FILE'])
    return redirect("/advanced")


@app.route("/edit/<int:entry_id>", methods=["GET"])
def edit_entry(entry_id):
    if not check_auth():
        return redirect(url_for("login"))
    entries = get_entries(db.session, session["user_id"])
    my_entries = [e for e in entries if e.id == entry_id]
    if len(my_entries) == 0:
        #TODO flash error msg about invalid ID here
        return redirect(url_for("login"))
    else:
        fe = decrypt_entries(my_entries, session['password'])
        print(fe[0])
        return render_template("new.html", e_id=entry_id, entry=fe[0], error=None)


@app.route("/entries/strength")
def password_strength():
    if check_auth():
        entries = get_entries(db.session, session["user_id"])
        dec_entries = decrypt_entries(entries, session['password'])
        entry_scores = password_strength_scores(session["email"], dec_entries)
        return render_template("password_strength.html", entry_scores=entry_scores)
    else:
        return redirect(url_for("login"))


@app.route("/entries/2fa")
def two_factor():
    if check_auth():
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
        return render_template("entries_2fa.html", two_factor_map=two_factor_map)
    else:
        return redirect(url_for("login"))


@app.route("/advanced")
def advanced():
    if not check_auth():
        return redirect(url_for("login"))
    return render_template("advanced.html")


@app.route("/profile")
def profile():
    if not check_auth():
        return redirect(url_for("login"))
    user = db.session.query(User).filter_by(id=session["user_id"]).one()
    user_prefs = {
        "default_random_password_length": user.default_random_password_length,
        "default_random_passphrase_length": user.default_random_passphrase_length,
    }
    return render_template("profile.html",
        title="PassZero &middot; Profile", user_prefs=user_prefs)


@app.route("/recover")
def recover_password():
    return render_template("recover.html")


@app.route("/recover/confirm")
def recover_password_confirm():
    try:
        token = request.args['token']
        token_obj = db.session.query(AuthToken).filter_by(token=token).one()
        if token_obj.is_expired():
            flash("Token has expired")
            # delete old token from database
            db.session.delete(token_obj)
            db.session.commit()
            return redirect(url_for("recover_password"))
        else:
            # token deleted when password changed
            return render_template("recover.html", confirm=True)
    except NoResultFound:
        flash("Token is invalid")
        return redirect(url_for("recover_password"))
    except KeyError:
        flash("Token is mandatory")
        return redirect(url_for("recover_password"))


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/version")
def get_version():
    return app.config['BUILD_ID']


app.wsgi_app = ProxyFix(app.wsgi_app)

if __name__ == "__main__":
    db.create_all()
    if DEBUG:
        app.debug = True
        assert(os.path.exists("cert.pem"))
        assert(os.path.exists("key.pem"))
        if 'NO_SSL' in os.environ:
            # used for testing service workers
            app.run(port=app.config['PORT'])
        else:
            app.run(port=app.config['PORT'], ssl_context=("cert.pem", "key.pem"))
    else:
        app.debug = False
        app.run(host='0.0.0.0', port=app.config['PORT'])
