from flask import request

from app.main import db
from app.main.model.newuser import sysUser, targetUser
from app.main.model.blacklist import BlackList
from typing import Dict, Tuple
from flask_jwt_extended import get_jwt_identity, get_jti, decode_token
from app.main.util.response_tip import *
from app.main.util.write_json_to_obj import wj2o

from flask_jwt_extended import get_jwt_identity, jwt_required, get_jwt
from datetime import datetime


from app.main.service.auth_helper import save_token
from app.main.util.permission import permission

@jwt_required()
def save_new_blackList(data):
    # 只有日志管理员和系统管理员可以添加和查看
    res = permission.getblackListsPer()
    if not res:
        return response_with(PERMISSION_ERROR_403)
    id = data.get('uid')
    try:
        sysuser = sysUser.query.filter_by(id=int(id)).first()
        print('被测用户',sysuser)
        save_token(sysuser, comments=data['comments'])
        return response_with(SUCCESS_201)
    except Exception as e:
        return response_with(ITEM_NOT_EXISTS)

@jwt_required()
def get_all_blackLists():
    res = permission.getblackListsPer()
    if not res:
        return response_with(PERMISSION_ERROR_403),403
    try:
        blackLists = db.session.query(BlackList.id, BlackList.jti, BlackList.uid, sysUser.username, BlackList.createdbyuid, sysUser.username, BlackList.operatetime, BlackList.comments).join(BlackList, sysUser.id==BlackList.uid).all()
        return blackLists
    except:
        return response_with(ITEM_NOT_EXISTS),400

@jwt_required()
def get_a_blackList(id):
    res = permission.getblackListsPer()
    if not res:
        return response_with(PERMISSION_ERROR_403),403
    try:
        blackList = db.session.query(BlackList.id, BlackList.jti, BlackList.uid, sysUser.username, BlackList.createdbyuid, sysUser.username, BlackList.operatetime).join(BlackList, sysUser.id==BlackList.uid).first()
        return blackList
    except Exception as e:
        # 异常处理
        print(e)
        return response_with(ITEM_NOT_EXISTS)

def delete_a_blacklist_func(id):
    try:
        # 删除黑名单
        blacklist = BlackList.query.filter_by(id=id).first()
        print('黑名单',blacklist)
        db.session.delete(blacklist)
        db.session.commit()
        return response_with(SUCCESS_200)
    except Exception as e:
        # 异常处理
        print(e)
        return response_with(ITEM_NOT_EXISTS)

@jwt_required()
def delete_a_blacklist(id):
    res = permission.getblackListsPer()
    if not res:
        return response_with(PERMISSION_ERROR_403), 403
    return delete_a_blacklist_func(id=id)

@jwt_required()
def delete_blacklists(IDs):
    res = permission.getblackListsPer()
    if not res:
        return response_with(PERMISSION_ERROR_403), 403

    for obj_id in IDs:
        resp = delete_a_blacklist_func(id=obj_id)
        resbody = resp.data.decode('utf-8')
        resbody = eval(resbody)
        if resbody['status'] != 'success':
            return resp
    db.session.commit()
    return response_with(SUCCESS_201)
