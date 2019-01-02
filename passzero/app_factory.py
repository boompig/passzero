import os
from datetime import timedelta

from flask import Blueprint, Flask, session
from flask_compress import Compress
from flask_cors import CORS
from flask_jwt_extended import JWTManager
from flask_talisman import Talisman
from jwt.exceptions import DecodeError
from sqlalchemy.orm.exc import NoResultFound
from werkzeug.contrib.fixers import ProxyFix

import passzero.config as pz_config
from passzero.api import api
from passzero.api_utils import generate_csrf_token
from passzero.api_v1 import api_v1
from passzero.api_v2 import api_v2
from passzero.main_routes import main_routes
from passzero.models import ApiToken, db


def create_app(name: str, settings_override: dict = {}):
    compress = Compress()

    app = Flask(name, static_url_path="")
    # allow CORS on /api/v3 (everything with an API key)
    CORS(app, resources={
        r"/api/v3/*": {"origins": "*"}
    })

    # add compress middleware
    compress.init_app(app)

    # necessary to fix some bugs in webservers?
    app.wsgi_app = ProxyFix(app.wsgi_app)

    # setup environment
    if os.path.exists("passzero/my_env.py"):
        from passzero.my_env import setup_env
        setup_env()

    # app config
    app.config.from_object(pz_config)
    app.config["SQLALCHEMY_DATABASE_URI"] = os.environ["DATABASE_URL"]
    app.config["DUMP_FILE"] = "passzero_dump.csv"
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["WTF_CSRF_ENABLED"] = False
    app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(minutes=5)
    app.config["WEB_SESSION_EXPIRES"] = timedelta(minutes=20)
    app.config["JWT_BLACKLIST_ENABLED"] = True
    app.config["JWT_BLACKLIST_TOKEN_CHECKS"] = ["access"]
    app.config["SWAGGER_UI_DOC_EXPANSION"] = "list"
    # remove whitespace from json responses through the API
    app.config["RESTPLUS_JSON"] = {
        "indent": None,
        "separators": (",", ":")
    }

    app.config.update(settings_override)

    jwt = JWTManager(app)

    @jwt.token_in_blacklist_loader
    def check_token_in_blacklist(token_dict: dict) -> bool:
        user_id = token_dict["identity"]["user_id"]
        try:
            api_token = db.session.query(ApiToken).filter_by(user_id=user_id).one()
            return api_token.token_identity != token_dict["jti"]
        except NoResultFound:
            # no token registered - may mean the token is revoked
            return True

    @api.errorhandler(DecodeError)
    @app.errorhandler(DecodeError)
    def error_handler(e):
        """Use this for when the JWT token is not valid"""
        return {
            "message": "Invalid token",
            "success": False
        }, 403

    # register blueprints
    app.register_blueprint(api_v1)
    app.register_blueprint(api_v2, prefix="/api/v2")
    app.register_blueprint(main_routes)

    # create swagger docs automatically and show them at /doc
    blueprint = Blueprint("api", __name__, url_prefix="/api")
    api.init_app(app)
    app.register_blueprint(blueprint)

    # register CSRF generation function
    app.jinja_env.globals["csrf_token"] = generate_csrf_token

    # create SSL secret keys
    if "FLASK_SECRET_KEY" in os.environ:
        app.secret_key = str(os.environ["FLASK_SECRET_KEY"])
        app.config["DEBUG"] = False
    else:
        app.config["DEBUG"] = True
        app.secret_key = "64f5abcf8369e362c36a6220128de068"

    Talisman(
        app,
        force_https_permanent=True,
        content_security_policy={
            "default-src": "\'self\'",
            # CDN for javascript
            "script-src": ["\'self\'", "cdnjs.cloudflare.com"],
            # CDN for CSS
            # NOTE: unsafe-inline is needed for tooltips
            "style-src": ["\'self\'", "\'unsafe-inline\'", "cdnjs.cloudflare.com", "use.fontawesome.com"],
            "font-src": ["use.fontawesome.com"],
            # NOTE: data: is needed for https://github.com/twbs/bootstrap/issues/25394
            "img-src": ["\'self\'", "data:"]
        }
    )

    @app.before_request
    def set_session_expiry():
        session.permanent = True
        app.permanent_session_lifetime = app.config["WEB_SESSION_EXPIRES"]
        session.modified = True

    # add the database
    db.app = app
    db.init_app(app)

    return app
