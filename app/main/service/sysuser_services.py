from flask import request

from app.main import db
from app.main.model.newuser import sysUser, targetUser
from typing import Dict, Tuple
from flask_jwt_extended import create_access_token
from app.main.util.response_tip import *
from app.main.util.write_json_to_obj import wj2o

from flask_jwt_extended import get_jwt_identity, jwt_required
from datetime import datetime



@jwt_required()
def operate_a_sysuser(id, operator):
    """
    操作包含：锁定|解锁、冻结|解冻、删除
    Args:
        id: user id
        operator:

    Returns:

    """
    tmp_sysuser = sysUser.query.filter_by(id=id).first()

    if not tmp_sysuser:
        return response_with(ITEM_NOT_EXISTS)

    if tmp_sysuser.isfreezed:
        # 用户被冻结，不能登录，也就不能进行相关操作，除解冻外，解冻还需检验操作对象权限
        # 暂不考虑操作权限
        if operator != "unfreeze":
            return response_with(ITEM_FREEZED_400)
        else:
            tmp_sysuser.isfreezed = False
    else:
        # 用户没有被冻结
        if operator == "freeze":
            tmp_sysuser.isfreezed = True
            tmp_sysuser.freezetime = datetime.now()
        else:
            if tmp_sysuser.islocked:
                if operator != "unlock":
                    return response_with(ITEM_LOCKED_400)
                else:
                    tmp_sysuser.islocked = False
            else:
                if operator == "lock":
                    tmp_sysuser.islocked = True
                    tmp_sysuser.lockedtime = datetime.now()
                elif operator == "delete":
                    db.session.delete(tmp_sysuser)
                else:
                    print("日怪")
                    return response_with(INVALID_INPUT_422)
    tmp_sysuser.modifiedbyuid = get_jwt_identity()
    tmp_sysuser.modifiedtime = datetime.now()
    db.session.commit()

    return response_with(SUCCESS_201)

def operate_sysusers(sysusers, operator):
    for item in sysusers:
        if item:
            try:
                operate_a_sysuser(item.id, operator)
                # db.session.commit()
            except Exception as e:
                error = f"组织{item.id}操作出错，操作符：{operator}".format()
                print(error)
                return response_with(error=error)
            return response_with(SUCCESS_201)

def check_input_update(inputData):
    res = True
    if 'email' in inputData.keys():
        sysuser = sysUser.query.filter_by(email=inputData['email']).first()
        taguser = targetUser.query.filter_by(email=inputData['email']).first()
        id = get_jwt_identity()
        if (sysuser and sysuser.id != id) or taguser:
            res = False
    if 'sysrole' in inputData.keys():
        inputData['sysrole'] = role_change(inputData['sysrole'])
    if ('password' in inputData.keys()) and (not inputData['password']):
        del inputData['password']
    return res, inputData

@jwt_required()
def update_a_sysuser(id):
    tmp_sysuser = sysUser.query.filter_by(id=id).first()
    if not tmp_sysuser:
        return response_with(ITEM_NOT_EXISTS)
    if tmp_sysuser.isfreezed == True:
        return response_with(ITEM_FREEZED_400)
    elif tmp_sysuser.islocked == True:
        return response_with(ITEM_LOCKED_400)
    update_val = request.json
    # 需验证进行编辑的数据是否正确，主要是email
    res, update_val = check_input_update(update_val)
    if not res:
        response_object = {
            'status': 'fail',
            'message': 'User already exists. ',
        }
        return response_object, 409
    update_val['modifiedbyuid'] = get_jwt_identity()
    update_val['modifiedtime'] = datetime.now()
    wj2o(tmp_sysuser, update_val)
    print('在编辑用户中',tmp_sysuser)
    save_changes(tmp_sysuser)
    response_object = {
        'code': 'success',
        'message': f'User {id} updated!'.format()
    }
    return response_object, 201

# 验证相应字段
def check_input(inputData):
    if 'username' not in inputData.keys():
        # 将用户邮箱默认为用户名
        inputData['username'] = inputData['email']
    if 'islocked' in inputData.keys():
        inputData['lockedtime'] = datetime.now()
        inputData['lockedbyuid'] = get_jwt_identity()
        print('get_jwt_identity()',get_jwt_identity())
    if 'isfreezed' in inputData.keys():
        inputData['freezetime'] = datetime.now()
        inputData['freezedbyuid'] = get_jwt_identity()
    inputData['createtime'] = datetime.now()
    inputData['createdbyuid'] = get_jwt_identity()
    return inputData

def role_change(role):
    res = ''
    if role == '系统管理员':
        print('进来啦')
        res = 'sysadmin'
    elif role == '日志管理员':
        res = 'logadmin'
    elif role == '项目管理员':
        res = 'projectadmin'
    else:
        res = 'representative'
    return res

@jwt_required()
def save_new_sysuser(data: Dict[str, str]) -> Tuple[Dict[str, str], int]:
    # 先转换用户角色
    request.json['sysrole'] = role_change(request.json['sysrole'])
    sysuser = sysUser.query.filter_by(email=data['email']).first()
    taguser = targetUser.query.filter_by(email=data['email']).first()
    print('成功了吗')
    if (not sysuser) and (not taguser):
        new_user = sysUser()
        # 判断用户是否输入用户名、锁定、冻结等参数
        print('前端上传的',request.json['sysrole'])
        new_data = check_input(request.json)
        wj2o(new_user, new_data)
        save_changes(new_user)
        return generate_token(new_user)
    else:
        response_object = {
            'status': 'fail',
            'message': 'User already exists. Please Log in.',
        }
        return response_object, 409

from sqlalchemy import or_, and_, not_, exists, select

from anytree import Node, RenderTree
from anytree.exporter import JsonExporter
def createTreeForSysuser():
    sysuser_objs = sysUser.query.all()
    for sysuser in sysuser_objs:
        if (sysuser.createdbyuid == 0):
            strcode = 'sysuser0 = Node(id={}, username="{}", )'.format(sysuser.id, sysuser.username, sysuser.email,
                                                                       sysuser.sysrole,
                                                                       sysuser.createtime, sysuser.createdbyuid,
                                                                       sysuser.mobile, sysuser.comments,
                                                                       sysuser.islocked, sysuser.lockedbyuid,
                                                                       sysuser.lockedtime, sysuser.isfreezed,
                                                                       sysuser.freezedbyuid, sysuser.freezetime,
                                                                       sysuser.modifiedbyuid,
                                                                       sysuser.modifiedtime)
            exec(strcode)
        else:
            strcode = 'sysuser{} = Node(id={}, name="{}", parent={})'.format(sysuser.id, sysuser.username,
                                                                             sysuser.email, sysuser.sysrole,
                                                                             sysuser.createtime, sysuser.createdbyuid,
                                                                             sysuser.mobile, sysuser.comments,
                                                                             sysuser.islocked, sysuser.lockedbyuid,
                                                                             sysuser.lockedtime, sysuser.isfreezed,
                                                                             sysuser.freezedbyuid, sysuser.freezetime,
                                                                             sysuser.modifiedbyuid,
                                                                             sysuser.modifiedtime,
                                                                             'sysuser' + str(sysuser.createdbyuid))
            exec(strcode)


def get_sysusers_byRole(id):
    resList = []
    sysuser = sysUser.query.filter_by(id=id).first()
    if sysuser.sysrole == 'sysadmin':
        # 查看该系统管理员下的所有用户，根据创建者ID进行判断
        # 直接：系统管理员、项目管理员、日志管理员、客户代表
        # 间接：项目管理员创建的客户代表或系统管理员创建的
        print('有上级吗',sysuser.create_user)
        resData_one = sysUser.query.filter(sysUser.createdbyuid==id).all()

        if sysuser.createdbyuid==id:
            pass
        resData = sysUser.query.filter(or_(sysUser.create_user.id == id, sysUser.create_user.create_user.id == id,
                                           sysUser.create_user.create_user.create_user.id == id)).all()

    elif sysuser.sysrole == 'projectadmin':
        # 直接：项目管理员创建的客户代表
        resData = sysUser.query.filter(sysUser.create_user.has(id=id)).all()
    else:
        testres = sysUser.query.filter(sysUser.create_user==id).all()
        print('测试',testres)
        resData = []
    return resData

# @jwt_required()
def get_all_sysusers():
    # 根据当前用户ID或系统角色进行判断
    # 系统管理员可以查看其下的所有用户（包括项目管理员、日志管理员、客户代表）
    print('返回的所有系统用户的数据类型',type(sysUser.query.all()))
    return sysUser.query.all()

def get_all_sysusers_test():
    # 根据当前用户ID或系统角色进行判断
    # 系统管理员可以查看其下的所有用户（包括项目管理员、日志管理员、客户代表）
    print('返回的所有系统用户的数据类型',type(sysUser.query.all()))
    id = get_jwt_identity()

    return sysUser.query.all()



def get_a_sysuser(id):
    return sysUser.query.filter_by(id=id).first()


def generate_token(sysuser: sysUser) -> Tuple[Dict[str, str], int]:
    try:
        # generate the auth token
        response_object = {
            'status': 'success',
            'message': 'Successfully registered.',
            'Authorization': create_access_token(sysuser.id)
        }
        return response_object, 201
    except Exception as e:
        response_object = {
            'status': 'fail',
            'message': 'Some error occurred. Please try again.' + str(e)
        }
        return response_object, 401


def save_changes(data: sysUser) -> None:
    db.session.add(data)
    db.session.commit()


def search_for_sysusers(data):
    print('数据',data)
    tmp_sysusers = sysUser.query
    try:
        if data['id']:
            tmp_sysusers = tmp_sysusers.filter_by(id=int(data['id']))
    except:
        print('无id')

    try:
        if data['partial_name']:
            tmp_sysusers = tmp_sysusers.filter(sysUser.username.like("%" + data['partial_name'] + "%"))
    except:
        print('无username')
    try:
        if data['createtime']:
            tmp_sysusers = tmp_sysusers.filter(sysUser.createtime >= data['createtime'])
    except:
        print('无createtime')
    try:
        if data['lockedtime']:
            tmp_sysusers = tmp_sysusers.filter(sysUser.lockedtime >= data['lockedtime'])
    except:
        print('无lockedtime')
    try:
        if data['freezedtime']:
            tmp_sysusers = tmp_sysusers.filter(sysUser.freezetime >= data['freezedtime'])
    except:
        print('无freezedtime')
    try:
        if data['sysrole']:
            tmp_sysusers = tmp_sysusers.filter(sysUser.sysrole.like("%" + data['sysrole'] + "%"))
    except:
        print('无sysrole')
    try:
        if data['status_freeze']:
            tmp_sysusers = tmp_sysusers.filter(sysUser.isfreezed==True)
    except:
        print('无status_freeze')
    try:
        print('status_lock',data['status_lock'])
        if data['status_lock']:
            tmp_sysusers = tmp_sysusers.filter(sysUser.islocked==True)
    except:
        print('无status_lock')
    # createdbyuid
    try:
        if data['createdbyuid']:
            tmp_sysusers = tmp_sysusers.filter_by(createdbyuid=int(data['createdbyuid']))
            print('查询结果',tmp_sysusers)
    except:
        print('无createdbyuid')
    try:
        if data['freezedbyuid']:
            tmp_sysusers = tmp_sysusers.filter_by(freezedbyuid=int(data['freezedbyuid']))
    except:
        print('无freezedbyuid')
    try:
        if data['modifiedbyuid']:
            tmp_sysusers = tmp_sysusers.filter_by(modifiedbyuid=int(data['modifiedbyuid']))
    except:
        print('无modifiedbyuid')
    try:
        if data['lockedbyuid']:
            tmp_sysusers = tmp_sysusers.filter_by(createdbyuid=int(data['lockedbyuid']))
    except:
        print('无lockedbyuid')
    return tmp_sysusers.all(), 201

