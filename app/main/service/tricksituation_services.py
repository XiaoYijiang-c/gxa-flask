from flask import request

from app.main import db
from app.main.model.newuser import sysUser, targetUser
from app.main.model.tricksituation import trickSituation
from typing import Dict, Tuple
from flask_jwt_extended import get_jwt_identity, get_jti, decode_token
from app.main.util.response_tip import *
from app.main.util.write_json_to_obj import wj2o

from flask_jwt_extended import get_jwt_identity, jwt_required, get_jwt
from datetime import datetime


from app.main.service.auth_helper import save_token
from app.main.util.permission import permissionForTrickSituation
from app.main.service.taguser_services import getIDSofSysAdmin, getRepreIDs_sysAdmin, getRepresentitiveIDs_currentProjAdmin

@jwt_required()
def get_all_tricksituations():
    # 根据用户角色能访问的被测用户的ID进行查询
    sysIDs_list = getIDSofSysAdmin()
    repIDs_list = getRepresentitiveIDs_currentProjAdmin()
    repIDs_sysadmin_list = getRepreIDs_sysAdmin()
    IDs_List = repIDs_list + sysIDs_list + repIDs_sysadmin_list
    res, resData = permissionForTrickSituation.getTrickSituationsPer(IDs_List=IDs_List)
    if res==2:
        return response_with(PERMISSION_ERROR_403, message='日志管理员没有操作权限')
    elif res==0:
        return response_with(SERVER_ERROR_404, message='请再试一次')
    else:
        tricksituationsLists = db.session.query(trickSituation.id, trickSituation.taguid, targetUser.username, trickSituation.taskid,trickSituation.tricktime, trickSituation.action, trickSituation.inputContent, trickSituation.comments).join(targetUser, targetUser.id==trickSituation).all()
        pass


@jwt_required()
def get_a_tricksituation(id):
    pass

@jwt_required()
def update_a_tricksituation():
    pass