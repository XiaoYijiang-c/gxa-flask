from flask import request

from app.main import db
from app.main.model.newuser import targetUser
from app.main.model.tricksituation import trickSituation
from app.main.util.response_tip import *
from app.main.util.write_json_to_obj import wj2o

from flask_jwt_extended import get_jwt_identity, jwt_required, get_jwt
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
        # 先过滤，再组合
        print('被测用户ID', resData)
        # tricksituations_filter = trickSituation.query.filter(trickSituation.taguid.in_(resData))
        # print('中招情况',tricksituations_filter.all())
        # print(db.session.query(trickSituation, targetUser.username).join(targetUser, targetUser.id == trickSituation.taguid).all())
        query = db.session.query(trickSituation, targetUser.username).join(targetUser, targetUser.id == trickSituation.taguid).filter(trickSituation.taguid.in_(resData))
        print('构造查询',query.all())
        tricksituationsLists = query.all()
        return tricksituationsLists


@jwt_required()
def get_a_tricksituation(id):
    sysIDs_list = getIDSofSysAdmin()
    repIDs_list = getRepresentitiveIDs_currentProjAdmin()
    repIDs_sysadmin_list = getRepreIDs_sysAdmin()
    IDs_List = repIDs_list + sysIDs_list + repIDs_sysadmin_list
    res, resData = permissionForTrickSituation.getTrickSituationsPer(IDs_List=IDs_List)
    print('权限查询结果', res, resData)
    if res == 2:
        return response_with(PERMISSION_ERROR_403, message='日志管理员没有操作权限'), 403
    elif res == 0:
        return response_with(SERVER_ERROR_404, message='请再试一次'), 404
    else:
        if int(id) not in resData:
            return response_with(PERMISSION_ERROR_403, message='当前系统用户没有查看权限')
        query = db.session.query(trickSituation, targetUser.username).join(targetUser,
                                                                           targetUser.id == trickSituation.taguid).filter(
            trickSituation.id == int(id))
        tricksituation = query.all()
        return tricksituation

@jwt_required()
def update_a_tricksituation(id):
    sysIDs_list = getIDSofSysAdmin()
    repIDs_list = getRepresentitiveIDs_currentProjAdmin()
    repIDs_sysadmin_list = getRepreIDs_sysAdmin()
    IDs_List = repIDs_list + sysIDs_list + repIDs_sysadmin_list
    res, resData = permissionForTrickSituation.getTrickSituationsPer(IDs_List=IDs_List)
    if res == 2:
        return response_with(PERMISSION_ERROR_403, message='日志管理员没有操作权限')
    elif res == 0:
        return response_with(SERVER_ERROR_404, message='请再试一次')
    else:
        if int(id) not in resData:
            return response_with(PERMISSION_ERROR_403, message='当前系统用户没有查看权限')
        # 编辑用户
        tmp_tricksituation = trickSituation.query.filter_by(id=int(id)).first()
        if not tmp_tricksituation:
            return response_with(ITEM_NOT_EXISTS, message='中招记录不存在')
        update_val = request.json
        wj2o(tmp_tricksituation, update_val)
        print('在编辑用户中', tmp_tricksituation)
        db.session.commit()
        response_object = {
            'code': 'success',
            'message': f'tricksituation {id} updated!'.format()
        }
        return response_object, 201
