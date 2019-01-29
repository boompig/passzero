from flask_restplus import Api
from passzero.api.api_token import ns as ApiTokenNamespace
from passzero.api.entry import ns as ApiEntryNamespace
from passzero.api.entry_list import ns as ApiEntryListNamespace
from passzero.api.link import ns as ApiLinkNamespace
from passzero.api.link_list import ns as ApiLinkListNamespace

api = Api(title="PassZero v3 API", version="3.0", doc="/doc/")

api.add_namespace(ApiTokenNamespace,
                  path="/api/v3/token")
api.add_namespace(ApiEntryListNamespace,
                  path="/api/v3/entries")
api.add_namespace(ApiEntryNamespace,
                  path="/api/v3/entries/<int:entry_id>")
api.add_namespace(ApiLinkListNamespace,
                  path="/api/v3/links")
api.add_namespace(ApiLinkNamespace,
                  path="/api/v3/links/<int:link_id>")
