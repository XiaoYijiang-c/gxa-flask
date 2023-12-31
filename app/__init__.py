from flask_restx import Api
from flask import Blueprint

from .main.controller.organization_controller import ns as organization_ns
from .main.controller.user_controller import ns as user_ns
from .main.controller.auth_controller import ns as auth_ns
from .main.controller.sysuser_controller import ns as sys_ns
from .main.controller.taguser_controller import ns as tag_ns
from .main.controller.blackList_controller import ns as blackList_ns
from .main.controller.tricksituation_controller import ns as tricksituation_ns

api_blueprint = Blueprint('flask-restx', __name__)
authorizations = {
    'apikey': {
        'type': 'apiKey',
        'in': 'header',
        'name': 'Authorization'
    }
}

api = Api(
    api_blueprint,
    title='PHISHING SYS',
    version='1.0',
    description="a phishing system's api",
    authorizations=authorizations,
    security='apikey'
)

api.add_namespace(organization_ns, path='/organization')
api.add_namespace(user_ns, path='/user')
api.add_namespace(auth_ns, path='/auth')
api.add_namespace(sys_ns, path='/sysuser')
api.add_namespace(tag_ns, path='/taguser')
api.add_namespace(blackList_ns, path='/blacklist')
api.add_namespace(tricksituation_ns, path='/tricksituation')
