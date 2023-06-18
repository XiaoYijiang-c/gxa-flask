from flask import request
from flask_jwt_extended import jwt_required
from flask_restx import Resource
from ..util.response_tip import *
from ..util.dto import SysUserDTO
from ..service.sysuser_services import *
from typing import Dict, Tuple


ns = SysUserDTO.ns
_sysuserIn = SysUserDTO.sysuserIn
_sysuserInUpdate = SysUserDTO.sysuserInUpdate
_sysuserOut = SysUserDTO.sysuserOut
_userIDsIn = SysUserDTO.userIDsIn
_searchWordsIn = SysUserDTO.searchWordsIn
_operateIn = SysUserDTO.operateIn

@ns.route('/')
class SysUserList(Resource):
    @ns.doc('list_of_registered_sysusers')
    # @admin_token_required
    @ns.marshal_list_with(_sysuserOut, envelope='children')
    def get(self):
        """List all registered sysusers"""
        print('获取所有系统用户')
        return get_all_sysusers()

    @ns.expect(_sysuserIn, validate=True)
    @ns.response(201, 'sysUser successfully created.')
    @ns.doc('create a new sysuser')
    def post(self) -> Tuple[Dict[str, str], int]:
        """Creates a new sysUser """
        data = request.json
        return save_new_sysuser(data=data)


@ns.route('/test')
class SysUserListTest(Resource):
    @ns.doc('list_of_registered_sysusers')
    # @admin_token_required
    @ns.marshal_list_with(_sysuserOut, envelope='children')
    def get(self):
        """List all registered sysusers"""
        print('获取所有系统用户')
        return get_all_sysusers_test()

    @ns.expect(_sysuserIn, validate=True)
    @ns.response(201, 'sysUser successfully created.')
    @ns.doc('create a new sysuser')
    def post(self) -> Tuple[Dict[str, str], int]:
        """Creates a new sysUser """
        data = request.json
        return save_new_sysuser(data=data)

@ns.route('/<id>')
@ns.param('id', 'The sysUser identifier')
@ns.response(404, 'sysUser not found.')
class SysUser(Resource):
    @ns.doc('get a sysuser')
    @ns.marshal_with(_sysuserOut)
    def get(self, id):
        """get a sysuser given its identifier"""
        sysuser = get_a_sysuser(id)
        print('查询结果',sysuser)
        if not sysuser:
            return response_with(INVALID_INPUT_422)
        else:
            return sysuser

    @ns.expect(_sysuserInUpdate, validate=True)
    @ns.response(201, 'sysUser successfully modified.')
    @ns.doc("update a sysuser's info")
    def put(self, id):
        """update a sysuser's info, status not included"""
        return update_a_sysuser(id)


# 过滤/查询
@ns.route('/search')
class SearchForSysUsers(Resource):
    """Sysuser view"""

    @ns.doc('list_of_registered_sysusers')
    @ns.marshal_list_with(_sysuserOut, envelope='children')
    @ns.expect(_searchWordsIn, validate=True)
    def post(self):
        """search for sysusers by id, partial_name, create_time, lockedtime, freezedtime, position, orgid"""
        data = request.json
        return search_for_sysusers(data)


# # 操作
@ns.route('/action/<operator>')
@ns.param('operator', 'such as freeze|unfreeze, lock|unlock etc')
@ns.response(404, 'sysuser not found.')
class PatchUsers(Resource):
    """Sysuser view"""
    @ns.doc('operate sysusers')
    @ns.expect(_userIDsIn, validate=True)
    def patch(self, operator):
        """modify the status of a user"""
        userIDs = request.json
        for id in userIDs['data']:
            operate_a_sysuser(id, operator)
        return response_with(SUCCESS_201)

# 对一个用户进行操作
@ns.route('/actionforasysuser/<id>')
@ns.response(404, 'sysuser not found.')
class OperateAUser(Resource):
    """ SysUser View"""

    @ns.expect(_operateIn, validate=True)
    def patch(self,id):
        """ operate a sysuser ,such as delete 、freeze|unfreeze、lock|unlock"""
        data = request.json
        print('前端上传的参数',data)
        # 对当前用户进行相应操作
        return operate_a_sysuser(id, data['operate'])
