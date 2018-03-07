import os

from werkzeug.contrib.profiler import ProfilerMiddleware

from passzero.app_factory import create_app
from passzero.models import db

app = create_app(__name__)

if __name__ == "__main__":
    db.create_all()
    if app.config["DEBUG"]:
        app.debug = True
        assert(os.path.exists("cert.pem"))
        assert(os.path.exists("key.pem"))
        if "PROFILE" in os.environ:
            app.config["PROFILE"] = True
            app.wsgi_app = ProfilerMiddleware(app.wsgi_app, restrictions=[30])
        if "NO_SSL" in os.environ:
            # used for testing service workers
            app.run(port=app.config["PORT"])
        else:
            app.run(port=app.config["PORT"], ssl_context=("cert.pem", "key.pem"))
    else:
        app.debug = False
        app.run(host="0.0.0.0", port=app.config["PORT"])
