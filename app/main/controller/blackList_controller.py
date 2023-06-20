from flask_restx import Resource
from ..util.response_tip import *
from ..util.dto import BlackListDTO
from ..service.blackList_services import *
from typing import Dict, Tuple

ns = BlackListDTO.ns
_blackListIn = BlackListDTO.blackListIn
_blackListOut = BlackListDTO.blackListOut
_blackListIDsIn = BlackListDTO.blackListIDsIn

@ns.route('/')
class BlackLists(Resource):
    @ns.response(403, 'permission forbidden')
    @ns.doc('list_of_blackList')
    # @admin_token_required
    @ns.marshal_list_with(_blackListOut, envelope='children')
    def get(self):
        """List all blackList"""
        print('获取所有黑名单用户')
        return get_all_blackLists()

    @ns.expect(_blackListIn, validate=True)
    @ns.response(201, 'sysUser successfully created.')
    @ns.response(403, 'permission forbidden')
    @ns.doc('create a new blackList')
    def post(self) -> Tuple[Dict[str, str], int]:
        """Creates a new sysUser """
        data = request.json
        return save_new_blackList(data=data)

    @ns.expect(_blackListIDsIn, validate=True)
    @ns.response(201, 'sysUser successfully delete.')
    @ns.response(403, 'permission forbidden')
    @ns.doc('delete a new blackList')
    def patch(self):
        blackListIDs = request.json
        # for id in blackListIDs['data']:
        #     res = delete_a_blacklist(id)
        #     if res.status!="success":
        #         return response_with(SERVER_ERROR_404)
        # return response_with(SUCCESS_201)
        return delete_blacklists(blackListIDs['data'])
@ns.route('/<id>')
@ns.param('id', 'The blackList identifier')
@ns.response(404, 'blackList not found.')
@ns.response(403, 'permission forbidden')
class BlackList(Resource):
    @ns.doc('delete a blackList')
    @ns.marshal_with(_blackListOut)
    def get(self, id):
        """get a blackList given its identifier"""
        res = get_a_blackList(id)
        print('返回结果',res)
        return res

    @ns.doc('delete a blackList')
    def delete(self, id):
        """delete a blackList given its identifier"""
        return delete_a_blacklist(id)
