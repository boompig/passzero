import logging
import os

from passzero.app_factory import create_app
from passzero.models import db

app = create_app(__name__)


if __name__ == "__main__":
    db.create_all()
    if app.config["DEBUG"]:
        app.debug = True
        app.logger.setLevel(logging.INFO)
        if "NO_SSL" in os.environ:
            # used for testing service workers
            app.run(port=app.config["PORT"])
        else:
            assert os.path.exists("cert.pem")
            assert os.path.exists("key.pem")
            app.run(port=app.config["PORT"], ssl_context=("cert.pem", "key.pem"))
    else:
        app.debug = False
        app.run(host="0.0.0.0", port=app.config["PORT"])
else:
    # combine gunicorn logging with flask logging
    # see https://trstringer.com/logging-flask-gunicorn-the-manageable-way/
    gunicorn_logger = logging.getLogger("gunicorn.error")
    app.logger.handlers = gunicorn_logger.handlers
    app.logger.setLevel(gunicorn_logger.level)
