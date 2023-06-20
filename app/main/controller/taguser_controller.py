from flask import request
from flask_jwt_extended import jwt_required
from flask_restx import Resource
from ..util.response_tip import *
from ..util.dto import TagUserDTO
from ..service.taguser_services import *
from typing import Dict, Tuple


ns = TagUserDTO.ns
_taguserIn_sysadmin = TagUserDTO.taguserIn_sysadmin
_taguserIn_representitive = TagUserDTO.taguserIn_representitive
_taguserInUpdate = TagUserDTO.taguserInUpdate
_taguserOut = TagUserDTO.taguserOut
_userIDsIn = TagUserDTO.userIDsIn
_searchWordsIn = TagUserDTO.searchWordsIn
_operateIn = TagUserDTO.operateIn

@ns.route('/')
class TagUserList(Resource):
    @ns.doc('list_of_registered_tagusers')
    # @admin_token_required
    @ns.marshal_list_with(_taguserOut, envelope='children')
    def get(self):
        """List all registered tagusers"""
        print('获取所有系统用户')
        return get_all_tagusers()

    @ns.expect(_taguserIn_sysadmin, validate=True)
    @ns.response(201, 'tagUser successfully created.')
    @ns.doc('create a new taguser')
    def post(self) -> Tuple[Dict[str, str], int]:
        """Creates a new tagUser """
        data = request.json
        return save_new_taguser_expRepre(data=data)

@ns.route('/representitive/')
class tagUserAddByRepresentitive(Resource):
    @ns.expect(_taguserIn_representitive, validate=True)
    @ns.response(201, 'tagUser successfully created.')
    @ns.doc('create a new taguser')
    def post(self) -> Tuple[Dict[str, str], int]:
        """Creates a new tagUser """
        data = request.json
        return save_new_taguser_byrepresentitive(data=data)

@ns.route('/<id>')
@ns.param('id', 'The tagUser identifier')
@ns.response(404, 'tagUser not found.')
class TagUser(Resource):
    @ns.doc('get a taguser')
    @ns.marshal_with(_taguserOut)
    def get(self, id):
        """get a taguser given its identifier"""
        # taguser = get_a_taguser(id)
        # print('查询结果',taguser)
        # if not taguser:
        #     return response_with(INVALID_INPUT_422)
        # else:
        #     return taguser
        res = get_a_taguser(id)
        print('返回结果', res)
        return res

    @ns.expect(_taguserInUpdate, validate=True)
    @ns.response(201, 'tagUser successfully modified.')
    @ns.doc("update a taguser's info")
    def put(self, id):
        """update a taguser's info, status not included"""
        res = update_a_taguser(id)
        return res


# 过滤/查询
@ns.route('/search')
class SearchForSysUsers(Resource):
    """Taguser view"""

    @ns.doc('list_of_registered_tagusers')
    @ns.marshal_list_with(_taguserOut, envelope='children')
    @ns.expect(_searchWordsIn, validate=True)
    def post(self):
        """search for tagusers by id, partial_name, create_time, lockedtime, freezedtime, position, orgid,etc"""
        data = request.json
        return search_for_tagusers(data)


# # 操作
@ns.route('/action/<operator>')
@ns.param('operator', 'such as freeze|unfreeze, lock|unlock etc')
@ns.response(404, 'taguser not found.')
class PatchUsers(Resource):
    """Taguser view"""
    @ns.doc('operate tagusers')
    @ns.expect(_userIDsIn, validate=True)
    def patch(self, operator):
        """modify the status of tagusers"""
        userIDs = request.json
        return operate_tagusers(userIDs['data'], operator)

# 对一个用户进行操作
@ns.route('/actionforataguser/<id>')
@ns.response(404, 'taguser not found.')
class OperateAUser(Resource):
    """ TagUser View"""

    @ns.expect(_operateIn, validate=True)
    def patch(self,id):
        """ operate a taguser ,such as delete 、freeze|unfreeze、lock|unlock"""
        data = request.json
        print('前端上传的参数',data)
        # 对当前用户进行相应操作
        return operate_a_taguser(id, data['operate'])
