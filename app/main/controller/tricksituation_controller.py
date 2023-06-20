from flask_restx import Resource
from ..util.response_tip import *
from ..util.dto import trickSituationDTO
from ..service.tricksituation_services import *
from typing import Dict, Tuple

ns = trickSituationDTO.ns
_trickSituationOut = trickSituationDTO.trickSituationOut
_trickSituationUpdate = trickSituationDTO.trickSituationUpdate

@ns.route('/')
class trickSituationLists(Resource):
    @ns.response(403, 'permission forbidden')
    @ns.doc('list_of_trickSituation')
    # @admin_token_required
    @ns.marshal_list_with(_trickSituationOut, envelope='children')
    def get(self):
        """List all blackList"""
        print('获取所有黑名单用户')
        return get_all_tricksituations()

@ns.route('/<id>')
@ns.param('id', 'The trickSituation identifier')
@ns.response(404, 'trickSituation not found.')
@ns.response(403, 'trickSituation forbidden')
class trickSituationList(Resource):
    @ns.doc('get a trickSituation')
    @ns.marshal_with(_trickSituationOut)
    def get(self, id):
        """get a trickSituation given its identifier"""
        res = get_a_tricksituation(id)
        print('返回结果',res)
        return res

    @ns.expect(_trickSituationUpdate, validate=True)
    @ns.response(201, 'trickSituation successfully be updated.')
    @ns.doc('update a trickSituation')
    def put(self, id):
        """update a trickSituation given its identifier"""
        update_a_tricksituation
        pass