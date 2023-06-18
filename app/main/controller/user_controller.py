from flask import request
from flask_jwt_extended import jwt_required
from flask_restx import Resource
from ..util.response_tip import *
from ..util.dto import UserDTO
# from ..service.user_service import save_new_user, get_all_users, get_a_user, get_users_by_org_id,operate_a_user,search_for_users,update_a_user
from ..service.user_service import *
from typing import Dict, Tuple


ns = UserDTO.ns
_userIn = UserDTO.userIn
_userOut = UserDTO.userOut
_userIDsIn = UserDTO.userIDsIn
_searchWordsIn = UserDTO.searchWordsIn
_operateIn = UserDTO.operateIn

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
        print('查询结果',user)
        if not user:
            return response_with(INVALID_INPUT_422)
        else:
            return user

    @ns.expect(_userIn, validate=True)
    @ns.response(201, 'User successfully modified.')
    @ns.doc("update a user's info")
    def put(self, id):
        """update a user's info, status not included"""
        return update_a_user(id)

@ns.route('/organization/<id>')
@ns.param('id', 'The organization identifier')
@ns.response(404, 'Organization not found.')
class User(Resource):
    @ns.doc('get users by organization id')
    @ns.marshal_with(_userOut, envelope='children')
    def get(self, id):
        """get a user given organization id"""
        users, http_code = get_users_by_org_id(id)
        if not users:
            return response_with(INVALID_INPUT_422)
        else:
            return users, 201


# 过滤/查询
@ns.route('/search')
class SearchForUsers(Resource):
    """user view"""

    @ns.doc('list_of_registered_users')
    @ns.marshal_list_with(_userOut, envelope='children')
    @ns.expect(_searchWordsIn, validate=True)
    def post(self):
        """search for users by id, partial_name, create_time, lockedtime, freezedtime, position, orgid"""
        data = request.json
        return search_for_users(data)


# # 操作
@ns.route('/action/<operator>')
@ns.param('operator', 'such as freeze|unfreeze, lock|unlock etc')
@ns.response(404, 'user not found.')
class PatchUsers(Resource):
    """user view"""
    @ns.doc('operate users')
    @ns.expect(_userIDsIn, validate=True)
    def patch(self, operator):
        """modify the status of a user"""
        userIDs = request.json
        for id in userIDs['data']:
            operate_a_user(id, operator)
        return response_with(SUCCESS_201)

# 对一个用户进行操作
@ns.route('/actionforauser/<id>')
@ns.response(404, 'user not found.')
class OperateAUser(Resource):
    """ User View"""
    @ns.expect(_operateIn, validate=True)
    def patch(self,id):
        """ operate a user ,such as delete 、freeze|unfreeze、lock|unlock"""
        data = request.json
        print('前端上传的参数',data)
        # 对当前用户进行相应操作
        return operate_a_user(id, data['operate'])
