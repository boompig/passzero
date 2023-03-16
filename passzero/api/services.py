from flask_restx import Namespace, Resource

from passzero.models import Service, db
from passzero.api.jwt_auth import authorizations

ns = Namespace("Service", authorizations=authorizations)


@ns.route("")
class ApiService(Resource):
    def get(self):
        """
        Return a list of services and their mapping to services

        Arguments
        ---------
        none

        Response
        --------
        Success:

            { "services": [<service model>, ...] }

        Status codes
        ------------
        - 200: success
        """
        services = db.session.query(Service).all()
        return {
            "services": [service.to_json() for service in services]
        }
