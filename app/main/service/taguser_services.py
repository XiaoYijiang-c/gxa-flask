from flask import request

from app.main import db
from app.main.model.newuser import targetUser, sysUser
from typing import Dict, Tuple
from flask_jwt_extended import create_access_token
from app.main.util.response_tip import *
from app.main.util.write_json_to_obj import wj2o

from flask_jwt_extended import get_jwt_identity, jwt_required
from datetime import datetime



@jwt_required()
def operate_a_taguser(id, operator):
    """
    操作包含：锁定|解锁、冻结|解冻、删除
    Args:
        id: user id
        operator:

    Returns:

    """
    tmp_taguser = targetUser.query.filter_by(id=id).first()

    if not tmp_taguser:
        return response_with(ITEM_NOT_EXISTS)

    if tmp_taguser.isfreezed:
        # 用户被冻结，不能登录，也就不能进行相关操作，除解冻外，解冻还需检验操作对象权限
        # 暂不考虑操作权限
        if operator != "unfreeze":
            return response_with(ITEM_FREEZED_400)
        else:
            tmp_taguser.isfreezed = False
    else:
        # 用户没有被冻结
        if operator == "freeze":
            tmp_taguser.isfreezed = True
            tmp_taguser.freezetime = datetime.now()
        else:
            if tmp_taguser.islocked:
                if operator != "unlock":
                    return response_with(ITEM_LOCKED_400)
                else:
                    tmp_taguser.islocked = False
            else:
                if operator == "lock":
                    tmp_taguser.islocked = True
                    tmp_taguser.lockedtime = datetime.now()
                elif operator == "delete":
                    db.session.delete(tmp_taguser)
                else:
                    print("日怪")
                    return response_with(INVALID_INPUT_422)
    tmp_taguser.modifiedbyuid = get_jwt_identity()
    tmp_taguser.modifiedtime = datetime.now()
    db.session.commit()

    return response_with(SUCCESS_201)

def operate_tagusers(taguserss, operator):
    for item in taguserss:
        if item:
            try:
                operate_a_taguser(item.id, operator)
                # db.session.commit()
            except Exception as e:
                error = f"组织{item.id}操作出错，操作符：{operator}".format()
                print(error)
                return response_with(error=error)
            return response_with(SUCCESS_201)

def check_input_update(inputData):
    res = True
    if 'email' in inputData.keys():
        taguser = targetUser.query.filter_by(email=inputData['email']).first()
        sysuser = sysUser.query.filter_by(email=inputData['email']).first()
        id = get_jwt_identity()
        if (taguser and taguser.id != id) or sysuser:
            res = False
    if 'orgid' in inputData.keys():
        inputData['orgid'] = int(inputData['orgid'])
    if 'representativeID' in inputData.keys():
        inputData['representativeID'] = int(inputData['representativeID'])
    return res, inputData

@jwt_required()
def update_a_taguser(id):
    tmp_taguser = targetUser.query.filter_by(id=id).first()
    if not tmp_taguser:
        return response_with(ITEM_NOT_EXISTS)
    if tmp_taguser.isfreezed == True:
        return response_with(ITEM_FREEZED_400)
    elif tmp_taguser.islocked == True:
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
    wj2o(tmp_taguser, update_val)
    print('在编辑用户中',tmp_taguser)
    save_changes(tmp_taguser)
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
    if 'orgid' in inputData.keys():
        inputData['orgid'] = int(inputData['orgid'])
    if 'representativeID' in inputData.keys():
        inputData['representativeID'] = int(inputData['representativeID'])
    inputData['createtime'] = datetime.now()
    inputData['createdbyuid'] = get_jwt_identity()
    return inputData

@jwt_required()
def save_new_taguser(data: Dict[str, str]) -> Tuple[Dict[str, str], int]:
    # 先转换用户角色
    taguser = targetUser.query.filter_by(email=data['email']).first()
    sysuser = sysUser.query.filter_by(email=data['email']).first()
    print('成功了吗')
    if (not taguser) and (not sysuser):
        new_user = targetUser()
        # 判断用户是否输入用户名、锁定、冻结等参数
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
def createTreeFortaguser():
    tauser_objs = targetUser.query.all()
    for taguser in tauser_objs:
        if (taguser.createdbyuid == 0):
            strcode = 'taguser0 = Node(id={}, username="{}", )'.format(taguser.id, taguser.username, taguser.email,
                                                                       taguser.sysrole,
                                                                       taguser.createtime, taguser.createdbyuid,
                                                                       taguser.mobile, taguser.comments,
                                                                       taguser.islocked, taguser.lockedbyuid,
                                                                       taguser.lockedtime, taguser.isfreezed,
                                                                       taguser.freezedbyuid, taguser.freezetime,
                                                                       taguser.modifiedbyuid,
                                                                       taguser.modifiedtime)
            exec(strcode)
        else:
            strcode = 'taguser{} = Node(id={}, name="{}", parent={})'.format(taguser.id, taguser.username,
                                                                             taguser.email, taguser.sysrole,
                                                                             taguser.createtime, taguser.createdbyuid,
                                                                             taguser.mobile, taguser.comments,
                                                                             taguser.islocked, taguser.lockedbyuid,
                                                                             taguser.lockedtime, taguser.isfreezed,
                                                                             taguser.freezedbyuid, taguser.freezetime,
                                                                             taguser.modifiedbyuid,
                                                                             taguser.modifiedtime,
                                                                             'taguser' + str(taguser.createdbyuid))
            exec(strcode)


def get_taguser_byRole(id):
    resList = []
    taguser = targetUser.query.filter_by(id=id).first()
    if taguser.sysrole == 'sysadmin':
        # 查看该系统管理员下的所有用户，根据创建者ID进行判断
        # 直接：系统管理员、项目管理员、日志管理员、客户代表
        # 间接：项目管理员创建的客户代表或系统管理员创建的
        print('有上级吗',taguser.create_user)
        resData_one = targetUser.query.filter(targetUser.createdbyuid==id).all()

        if taguser.createdbyuid==id:
            pass
        resData = targetUser.query.filter(or_(targetUser.create_user.id == id, targetUser.create_user.create_user.id == id,
                                           targetUser.create_user.create_user.create_user.id == id)).all()

    elif taguser.sysrole == 'projectadmin':
        # 直接：项目管理员创建的客户代表
        resData = targetUser.query.filter(targetUser.create_user.has(id=id)).all()
    else:
        testres = targetUser.query.filter(targetUser.create_user==id).all()
        print('测试',testres)
        resData = []
    return resData

# @jwt_required()
def get_all_tagusers():
    # 根据当前用户ID或系统角色进行判断
    # 系统管理员可以查看其下的所有用户（包括项目管理员、日志管理员、客户代表）
    print('返回的所有系统用户的数据类型',type(targetUser.query.all()))
    return targetUser.query.all()

def get_all_tagusers_test():
    # 根据当前用户ID或系统角色进行判断
    # 系统管理员可以查看其下的所有用户（包括项目管理员、日志管理员、客户代表）
    print('返回的所有系统用户的数据类型',type(targetUser.query.all()))
    id = get_jwt_identity()

    return targetUser.query.all()



def get_a_taguser(id):
    return targetUser.query.filter_by(id=id).first()


def generate_token(taguser: targetUser) -> Tuple[Dict[str, str], int]:
    try:
        # generate the auth token
        response_object = {
            'status': 'success',
            'message': 'Successfully registered.',
            'Authorization': create_access_token(taguser.id)
        }
        return response_object, 201
    except Exception as e:
        response_object = {
            'status': 'fail',
            'message': 'Some error occurred. Please try again.' + str(e)
        }
        return response_object, 401


def save_changes(data: targetUser) -> None:
    db.session.add(data)
    db.session.commit()


def search_for_tagusers(data):
    print('数据',data)
    tmp_tagusers = targetUser.query
    try:
        if data['id']:
            tmp_tagusers = tmp_tagusers.filter_by(id=int(data['id']))
    except:
        print('无id')

    try:
        if data['partial_name']:
            tmp_tagusers = tmp_tagusers.filter(targetUser.username.like("%" + data['partial_name'] + "%"))
    except:
        print('无username')
    try:
        if data['createtime']:
            tmp_tagusers = tmp_tagusers.filter(targetUser.createtime >= data['createtime'])
    except:
        print('无createtime')
    try:
        if data['lockedtime']:
            tmp_tagusers = tmp_tagusers.filter(targetUser.lockedtime >= data['lockedtime'])
    except:
        print('无lockedtime')
    try:
        if data['freezedtime']:
            tmp_tagusers = tmp_tagusers.filter(targetUser.freezetime >= data['freezedtime'])
    except:
        print('无freezedtime')
    try:
        if data['representativeID']:
            tmp_tagusers = tmp_tagusers.filter(targetUser.representativeID==data['representativeID'])
    except:
        print('无representativeID')
    try:
        if data['status_freeze']:
            tmp_tagusers = tmp_tagusers.filter(targetUser.isfreezed==True)
    except:
        print('无status_freeze')
    try:
        print('status_lock',data['status_lock'])
        if data['status_lock']:
            tmp_tagusers = tmp_tagusers.filter(targetUser.islocked==True)
    except:
        print('无status_lock')
    # createdbyuid
    try:
        if data['createdbyuid']:
            tmp_tagusers = tmp_tagusers.filter_by(createdbyuid=int(data['createdbyuid']))
            print('查询结果',tmp_tagusers)
    except:
        print('无createdbyuid')
    try:
        if data['freezedbyuid']:
            tmp_tagusers = tmp_tagusers.filter_by(freezedbyuid=int(data['freezedbyuid']))
    except:
        print('无freezedbyuid')
    try:
        if data['modifiedbyuid']:
            tmp_tagusers = tmp_tagusers.filter_by(modifiedbyuid=int(data['modifiedbyuid']))
    except:
        print('无modifiedbyuid')
    try:
        if data['lockedbyuid']:
            tmp_tagusers = tmp_tagusers.filter_by(createdbyuid=int(data['lockedbyuid']))
    except:
        print('无lockedbyuid')
    return tmp_tagusers.all(), 201

