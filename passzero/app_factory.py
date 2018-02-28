import os

from flask import Flask
from flask_compress import Compress
from flask_sslify import SSLify
from werkzeug.contrib.fixers import ProxyFix

import passzero.config as pz_config
from passzero.api_utils import generate_csrf_token
from passzero.api_v1 import api_v1
from passzero.api_v2 import api_v2
from passzero.main_routes import main_routes
from passzero.models import db


def create_app(name: str, settings_override: dict = {}):
    compress = Compress()

    app = Flask(name, static_url_path="")

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
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ['DATABASE_URL']
    app.config['DUMP_FILE'] = "passzero_dump.csv"
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['WTF_CSRF_ENABLED'] = False

    app.config.update(settings_override)

    # register blueprints
    app.register_blueprint(api_v1)
    app.register_blueprint(api_v2, prefix="/api/v2")
    app.register_blueprint(main_routes)

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
