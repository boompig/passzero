from flask import Flask, render_template, redirect, session, request, url_for, escape, flash, make_response
from flask.ext.compress import Compress
from flask_sslify import SSLify
from passzero.api_v1 import api_v1
from passzero.api_v2 import api_v2
from passzero.api_utils import generate_csrf_token, check_auth
from passzero.backend import get_entries, decrypt_entries, activate_account
from passzero.datastore_postgres import db_export
from passzero.models import db, User, AuthToken
from sqlalchemy.orm.exc import NoResultFound
from werkzeug.contrib.fixers import ProxyFix
import os
import passzero.config as pz_config


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


@app.route("/logout", methods=["GET"])
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
    return render_template("new.html", error=None)


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
    fe = decrypt_entries(my_entries, session['password'])
    if len(fe) == 0:
        #TODO flash error msg about invalid ID here
        return redirect(url_for("login"))
    else:
        return render_template("new.html", e_id=entry_id, entry=fe[0], error=None)


@app.route("/advanced")
def advanced():
    if check_auth():
        return render_template("advanced.html")
    else:
        return redirect(url_for("login"))


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
        app.run(port=app.config['PORT'], ssl_context=("cert.pem", "key.pem"))
    else:
        app.debug = False
        app.run(host='0.0.0.0', port=app.config['PORT'])
