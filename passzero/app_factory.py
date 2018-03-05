import os
from datetime import timedelta

from flask import Flask, Blueprint
from flask_compress import Compress
from flask_jwt_extended import JWTManager
from flask_restplus import Api
from flask_sslify import SSLify
from werkzeug.contrib.fixers import ProxyFix
from flask_cors import CORS

import passzero.config as pz_config
from passzero.api.api_token import ApiTokenResource
from passzero.api.entry_list import ApiEntryList
from passzero.api.entry import ApiEntry
from passzero.api_utils import generate_csrf_token
from passzero.api_v1 import api_v1
from passzero.api_v2 import api_v2
from passzero.main_routes import main_routes
from passzero.models import db, ApiToken
from sqlalchemy.orm.exc import NoResultFound


def create_app(name: str, settings_override: dict = {}):
    compress = Compress()

    app = Flask(name, static_url_path="")
    # allow CORS on /api/v3 (everything with an API key)
    CORS(app, resources={r"/api/v3/*": { "origins": "*" } })

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
    app.config["JWT_BLACKLIST_ENABLED"] = True
    app.config["JWT_BLACKLIST_TOKEN_CHECKS"] = ["access"]

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

    # register blueprints
    app.register_blueprint(api_v1)
    app.register_blueprint(api_v2, prefix="/api/v2")
    app.register_blueprint(main_routes)

    # create swagger docs automatically and show them at /doc
    blueprint = Blueprint("api", __name__, url_prefix="/api")
    api = Api(app, doc="/doc/")
    app.register_blueprint(blueprint)

    api.add_resource(ApiTokenResource, "/api/v3/token")
    api.add_resource(ApiEntryList, "/api/v3/entries")
    api.add_resource(ApiEntry, "/api/v3/entries/<int:entry_id>")

    # register CSRF generation function
    app.jinja_env.globals["csrf_token"] = generate_csrf_token

    # create SSL secret keys
    if 'FLASK_SECRET_KEY' in os.environ:
        app.secret_key = str(os.environ["FLASK_SECRET_KEY"])
        SSLify(app, permanent=True)
        app.config['DEBUG'] = False
    else:
        if 'NO_SSL' not in os.environ:
            SSLify(app, permanent=True)
        app.secret_key = '64f5abcf8369e362c36a6220128de068'
        app.config['DEBUG'] = True

    # add the database
    db.app = app
    db.init_app(app)

    return app
