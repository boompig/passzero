from flask_restplus import Namespace, Resource

from ..models import Service, db
from .jwt_auth import authorizations

ns = Namespace("Service", authorizations=authorizations)


@ns.route("")
class ApiLink(Resource):
    def get(self):
        """
        Return a list of services and their mapping to services
        """
        services = db.session.query(Service).all()
        return {
            "services": [service.to_json() for service in services]
        }
