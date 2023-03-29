"""
See flask-restx API scaling using namespaces
https://flask-restx.readthedocs.io/en/latest/scaling.html
"""

from flask_restx import Api
from passzero.api.api_token import ns as ApiTokenNamespace
from passzero.api.document_list import ns as ApiDocumentListNamespace
from passzero.api.entry import ns as ApiEntryNamespace
from passzero.api.entry_list import ns as ApiEntryListNamespace
from passzero.api.link import ns as ApiLinkNamespace
from passzero.api.link_list import ns as ApiLinkListNamespace
from passzero.api.recovery import ns as ApiRecoveryNamespace
from passzero.api.services import ns as ApiServicesNamespace
from passzero.api.status import ns as ApiStatusNamespace
from passzero.api.user import ns as ApiUserNamespace

api = Api(title="PassZero v3 API", version="3.0", doc="/doc/")

api.add_namespace(ApiDocumentListNamespace,
                  path="/api/v3/documents")
api.add_namespace(ApiEntryListNamespace,
                  path="/api/v3/entries")
api.add_namespace(ApiEntryNamespace,
                  path="/api/v3/entries/<int:entry_id>")
api.add_namespace(ApiLinkListNamespace,
                  path="/api/v3/links")
api.add_namespace(ApiLinkNamespace,
                  path="/api/v3/links/<int:link_id>")
api.add_namespace(ApiRecoveryNamespace,
                  path="/api/v3/recover")
api.add_namespace(ApiServicesNamespace,
                  path="/api/v3/services")
api.add_namespace(ApiStatusNamespace,
                  path="/api/v3/status")
api.add_namespace(ApiTokenNamespace,
                  path="/api/v3/token")
api.add_namespace(ApiUserNamespace,
                  path="/api/v3/user")
