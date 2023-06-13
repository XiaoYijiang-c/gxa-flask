from flask import request
from flask_jwt_extended import jwt_required
from flask_restx import Resource
from ..util.response_tip import *
from ..util.dto import UserDTO
from ..service.user_service import save_new_user, get_all_users, get_a_user, get_users_by_org_id
from typing import Dict, Tuple


ns = UserDTO.ns
_userIn = UserDTO.userIn
_userOut = UserDTO.userOut


@ns.route('/')
class UserList(Resource):
    # @jwt_required
    @ns.doc('list_of_registered_users')
    # @admin_token_required
    @ns.marshal_list_with(_userOut, envelope='children')
    def get(self):
        """List all registered users"""
        return get_all_users()

    @ns.expect(_userIn, validate=True)
    @ns.response(201, 'User successfully created.')
    @ns.doc('create a new user')
    def post(self) -> Tuple[Dict[str, str], int]:
        """Creates a new User """
        data = request.json
        return save_new_user(data=data)


@ns.route('/<id>')
@ns.param('id', 'The User identifier')
@ns.response(404, 'User not found.')
class User(Resource):
    @ns.doc('get a user')
    @ns.marshal_with(_userOut)
    def get(self, id):
        """get a user given its identifier"""
        user = get_a_user(id)
        if not user:
            return response_with(INVALID_INPUT_422)
        else:
            return user
    @ns.doc('get a user')
    @ns.marshal_with(_userOut)
    def patch(self, id):
        """get a user given its identifier"""
        user = get_a_user(id)
        if not user:
            return response_with(INVALID_INPUT_422)
        else:
            return user

@ns.route('/organization/<id>')
@ns.param('id', 'The organization identifier')
@ns.response(404, 'Organization not found.')
class User(Resource):
    @ns.doc('get users by organization id')
    @ns.marshal_with(_userOut, envelope='children')
    def get(self, id):
        """get a user given its identifier"""
        users, http_code = get_users_by_org_id(id)
        if not users:
            return response_with(INVALID_INPUT_422)
        else:
            return users, 201
