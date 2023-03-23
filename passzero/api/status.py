from flask_restx import Namespace, Resource

from passzero.api.jwt_auth import authorizations

ns = Namespace("ApiStatus", authorizations=authorizations)


@ns.route("")
class ApiStatus(Resource):
    def get(self):
        return {"status": "ok"}
