import binascii
import json
import os
from datetime import timedelta

from flask import Blueprint, Flask, session
from flask_compress import Compress
from flask_cors import CORS
from flask_jwt_extended import JWTManager
from flask_talisman import Talisman
from jwt.exceptions import DecodeError
from sqlalchemy.orm.exc import NoResultFound
from werkzeug.middleware.proxy_fix import ProxyFix
from whitenoise import WhiteNoise

from passzero import crypto_utils
from passzero.api import api
from passzero.api_utils import generate_csrf_token
from passzero.api_v1 import api_v1
from passzero.api_v2 import api_v2
from passzero.config import DefaultConfig
from passzero.main_routes import main_routes
from passzero.models import ApiToken, db


def dict_to_base64(d: dict) -> str:
    # NOTE: internal use only
    s = binascii.b2a_base64(json.dumps(d).encode('utf-8')).rstrip()
    return s.decode('utf-8')


def read_database_uri() -> str:
    assert "DATABASE_URL" in os.environ, "DATABASE_URL environment variable must be set"

    uri = os.environ["DATABASE_URL"]
    if uri.startswith("postgres://"):
        # SQLAlchemy v1.4+ expects the postgresql:// scheme
        uri = uri.replace("postgres://", "postgresql://", 1)
    return uri


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
    app.wsgi_app = ProxyFix(app.wsgi_app)  # type: ignore

    # setup environment
    if os.path.exists("passzero/my_env.py"):
        from passzero.my_env import setup_env
        setup_env()

    # app config
    app.config.from_object(DefaultConfig)
    app.config["SQLALCHEMY_DATABASE_URI"] = read_database_uri()
    app.config["OFFLINE"] = os.environ.get("OFFLINE", "0") == "1"
    if app.config["OFFLINE"]:
        print("Working offline")
    if "PORT" in os.environ:
        # overwrite default port with environment variable
        app.config["PORT"] = os.environ["PORT"]
    # app.config["DISABLE_LOGOUT_TIMER"] = os.environ.get("DISABLE_LOGOUT_TIMER", "0") == "1"
    # if app.config["DISABLE_LOGOUT_TIMER"]:
    #     print("logout timer disabled")
    app.config["DUMP_FILE"] = "passzero_dump.csv"
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["WTF_CSRF_ENABLED"] = False
    app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(minutes=5)
    app.config["WEB_SESSION_EXPIRES"] = timedelta(minutes=20)
    app.config["SWAGGER_UI_DOC_EXPANSION"] = "list"
    assert "SENDGRID_API_KEY" in os.environ, "SENDGRID_API_KEY must be present in environment variables"
    app.config["SENDGRID_API_KEY"] = os.environ["SENDGRID_API_KEY"]
    # remove whitespace from json responses through the API
    app.config["RESTPLUS_JSON"] = {
        "indent": None,
        "separators": (",", ":")
    }

    app.config.update(settings_override)

    jwt = JWTManager(app)

    @jwt.token_in_blocklist_loader
    def check_token_in_blocklist(jwt_header, jwt_payload: dict) -> bool:
        # see https://flask-jwt-extended.readthedocs.io/en/stable/blocklist_and_token_revoking/
        user_id = jwt_payload["sub"]["user_id"]
        try:
            api_token = db.session.query(ApiToken).filter_by(user_id=user_id).one()
            return api_token.token_identity != jwt_payload["jti"]
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
    app.jinja_env.globals["to_base64"] = dict_to_base64

    # create SSL secret keys
    if "FLASK_SECRET_KEY" in os.environ:
        app.logger.info("Using stored FLASK_SECRET_KEY as secret key")
        app.secret_key = str(os.environ["FLASK_SECRET_KEY"])
        app.config["DEBUG"] = False
    elif "FLASK_ENV" in os.environ and os.environ["FLASK_ENV"] == "production":
        app.logger.info("Running in production. Generating random secret key...")
        app.config["DEBUG"] = False
        app.secret_key = crypto_utils.random_bytes(32)
    else:
        # NOTE: just used for local debugging, do not use in production
        app.config["DEBUG"] = True
        app.secret_key = "64f5abcf8369e362c36a6220128de068"

    csp = {
        "default-src": "\'self\'",
        # CDN for javascript
        "script-src": ["\'self\'", "cdnjs.cloudflare.com", "\'wasm-unsafe-eval\'"],
        # CDN for CSS
        # NOTE: unsafe-inline is needed for tooltips
        "style-src": ["\'self\'", "\'unsafe-inline\'", "cdnjs.cloudflare.com"],
        "font-src": ["cdnjs.cloudflare.com"],
        # NOTE: data: is needed for https://github.com/twbs/bootstrap/issues/25394
        "img-src": ["\'self\'", "data:"],
    }
    if app.config["DEBUG"]:
        # allow eval in DEBUG mode for React devtools
        assert isinstance(csp["script-src"], list)
        csp["script-src"].extend(["\'unsafe-eval\'", "\'unsafe-inline\'"])

    Talisman(
        app,
        force_https_permanent=True,
        content_security_policy=csp
    )

    @app.before_request
    def set_session_expiry():
        session.permanent = True
        app.permanent_session_lifetime = app.config["WEB_SESSION_EXPIRES"]
        session.modified = True

    # add the database
    db.app = app
    db.init_app(app)

    # enable WhiteNoise for more efficient treatment of static files
    app.wsgi_app = WhiteNoise(app.wsgi_app, root="static/")  # type: ignore

    return app
