from flask_restplus import Api
from passzero.api.api_token import ns as ApiTokenNamespace
from passzero.api.entry import ns as ApiEntryNamespace
from passzero.api.entry_list import ns as ApiEntryListNamespace

api = Api(title="PassZero v3 API", version="3.0", doc="/doc/")

api.add_namespace(ApiTokenNamespace,
                  path="/api/v3/token")
api.add_namespace(ApiEntryListNamespace,
                  path="/api/v3/entries")
api.add_namespace(ApiEntryNamespace,
                  path="/api/v3/entries/<int:entry_id>")
