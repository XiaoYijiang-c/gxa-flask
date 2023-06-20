from flask import request

from app.main import db
from app.main.model.newuser import targetUser, sysUser
from app.main.service.sysuser_services import getIDSofSysAdmin, getRepreIDs_sysAdmin
from app.main.model.organization import Organization
from typing import Dict, Tuple
from flask_jwt_extended import create_access_token
from app.main.util.response_tip import *
from app.main.util.write_json_to_obj import wj2o

from flask_jwt_extended import get_jwt_identity, jwt_required
from datetime import datetime
from app.main.util.permission import permissionForTaguser

def getRepresentitiveIDs_currentProjAdmin():
    # 当前项目管理员创建的客户代表
    id = get_jwt_identity()
    repIDs = sysUser.query.filter(and_(sysUser.sysrole == 'representative', sysUser.createdbyuid == id)).with_entities(sysUser.id).all()
    repIDs_list = [ID[0] for ID in repIDs]
    return repIDs_list

def operate_a_taguser_func(tmp_taguser,operator):
    """
    操作包含：锁定|解锁、冻结|解冻、删除
    Args:
        id: user id
        operator:
    Returns:
    """
    # tmp_taguser = targetUser.query.filter_by(id=id).first()
    if not tmp_taguser:
        return response_with(ITEM_NOT_EXISTS)
    if tmp_taguser.isfreezed:
        # 用户被冻结，不能登录，也就不能进行相关操作，除解冻外，解冻还需检验操作对象权限
        # 暂不考虑操作权限
        if operator != "unfreeze":
            if operator == 'freeze':
                pass
            else:
                return response_with(ITEM_LOCKED_400, message='对象：'+tmp_taguser.username+'被冻结')
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
                    if operator == 'lock':
                        pass
                    else:
                        return response_with(ITEM_LOCKED_400, message='对象：'+tmp_taguser.username+'被锁住')
                else:
                    tmp_taguser.islocked = False
            else:
                if operator == "lock":
                    tmp_taguser.islocked = True
                    tmp_taguser.lockedtime = datetime.now()
                elif operator == "delete":
                    db.session.delete(tmp_taguser)
                    # 将该普通用户下的中招记录也删除
                elif operator == "unlock":
                    pass
                else:
                    return response_with(INVALID_INPUT_422, message='输入内容无效')
    tmp_taguser.modifiedbyuid = get_jwt_identity()
    tmp_taguser.modifiedtime = datetime.now()
    return response_with(SUCCESS_201)

@jwt_required()
def operate_a_taguser(id, operator):
    repIDs_list = getRepresentitiveIDs_currentProjAdmin()
    repIDs_sysadmin_list = getRepreIDs_sysAdmin()
    IDs = repIDs_list + repIDs_sysadmin_list
    res, taguser = permissionForTaguser.operationPerForATaguser(obj_id=id, IDs=IDs)
    if res == 2:
        return response_with(PERMISSION_ERROR_403), 403
    elif res == 0:
        return response_with(INVALID_INPUT_422), 422
    else:
        resp = operate_a_taguser_func(tmp_taguser=taguser, operator=operator)
        resbody = resp.data.decode('utf-8')
        resbody = eval(resbody)
        if resbody['status'] == 'success':
            db.session.commit()
        return resp

@jwt_required()
def operate_tagusers(IDList, operator):
    repIDs_list = getRepresentitiveIDs_currentProjAdmin()
    repIDs_sysadmin_list = getRepreIDs_sysAdmin()
    IDs = repIDs_list + repIDs_sysadmin_list
    res, respData = permissionForTaguser.operationPerForATagusers(obj_IDs=IDList, IDs=IDs)
    if res == 2:
        return response_with(PERMISSION_ERROR_403, message='对'+str(respData)+'没有该操作权限')
    elif res == 0:
        return response_with(INVALID_INPUT_422, message='请再试一次')
    else:
        for tmp_taguser in respData:
            try:
                resp = operate_a_taguser_func(tmp_taguser, operator)
                resbody = resp.data.decode('utf-8')
                resbody = eval(resbody)
                if resbody['status'] != 'success':
                    return resp
            except Exception as e:
                error = f"被测用户{tmp_taguser.username}操作出错，操作符：{operator}".format()
                print(error)
                return response_with(error=error)
        db.session.commit()
        return response_with(SUCCESS_201)

def check_input_update(inputData, id):
    res = True
    if 'email' in inputData.keys():
        taguser = targetUser.query.filter_by(email=inputData['email']).first()
        sysuser = sysUser.query.filter_by(email=inputData['email']).first()
        if (taguser and taguser.id != int(id)) or sysuser:
            res = False
    if 'orgid' in inputData.keys():
        # 获取所有组织ID
        # IDs = Organization.query.with_entities(Organization.id).all()
        # IDs_list = [ID[0] for ID in IDs]
        # # 判断orgid是否存在于IDs中
        # if int(inputData['orgid']) not in IDs_list:
        #   raise ValueError({'error': '所选组织不存在'})
        inputData['orgid'] = int(inputData['orgid'])
    if 'representativeID' in inputData.keys():
        # repIDs = sysUser.query.filter(sysUser.sysrole == 'representative').with_entities(sysUser.id).all()
        # repIDs_list = [ID[0] for ID in repIDs]
        # if int(inputData['representativeID']) not in repIDs_list:
        #     raise ValueError({'error': '所选客户代表不存在'})
        inputData['representativeID'] = int(inputData['representativeID'])
    return res, inputData

@jwt_required()
def update_a_taguser( id ):
    repIDs_list = getRepresentitiveIDs_currentProjAdmin()
    repIDs_sysadmin_list = getRepreIDs_sysAdmin()
    IDs = repIDs_list + repIDs_sysadmin_list
    res, tmp_taguser = permissionForTaguser.operationPerForATaguser(obj_id=id, IDs=IDs)
    print('权限认证结果',res)
    if res == 2:
        return response_with(PERMISSION_ERROR_403, message='当前用户没有编辑'+tmp_taguser.username+'的权限')
    elif res == 0:
        return response_with(ITEM_NOT_EXISTS, message='用户不存在')
    else:
        # tmp_taguser = targetUser.query.filter_by(id=id).first()
        if not tmp_taguser:
            return response_with(ITEM_NOT_EXISTS)
        if tmp_taguser.isfreezed == True:
            return response_with(ITEM_FREEZED_400)
        elif tmp_taguser.islocked == True:
            return response_with(ITEM_LOCKED_400)
        update_val = request.json
        # 需验证进行编辑的数据是否正确，主要是email
        resp, update_val = check_input_update(update_val, id=id)
        print('更新检验', resp)
        if not resp:
            response_object = {
                'status': 'fail',
                'message': 'User already exists. ',
            }
            return response_object, 409
        update_val['modifiedbyuid'] = get_jwt_identity()
        update_val['modifiedtime'] = datetime.now()
        wj2o(tmp_taguser, update_val)
        print('在编辑用户中',tmp_taguser)
        db.session.commit()
        response_object = {
            'code': 'success',
            'message': f'User {id} updated!'.format()
        }
        return response_object, 201

# 验证相应字段
def check_input(inputData):
    id = get_jwt_identity()
    sysuser = sysUser.query.filter_by(id=int(id)).first()
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
    if ('representativeID' in inputData.keys()) and (sysuser.sysrole!='representative'):
        inputData['representativeID'] = int(inputData['representativeID'])
    else:
        inputData['representativeID'] = id
    inputData['createtime'] = datetime.now()
    inputData['createdbyuid'] = get_jwt_identity()
    return inputData

def save_new_taguser(data):
    taguser = targetUser.query.filter_by(email=data['email']).first()
    sysuser = sysUser.query.filter_by(email=data['email']).first()
    print('成功了吗')
    if (not taguser) and (not sysuser):
        new_user = targetUser()
        # 判断用户是否输入用户名、锁定、冻结等参数
        new_data = check_input(request.json)
        wj2o(new_user, new_data)
        save_changes(new_user)
        return response_with(SUCCESS_201)
    else:
        response_object = {
            'status': 'fail',
            'message': 'User already exists. Please Log in.',
        }
        return response_object, 409

@jwt_required()
def save_new_taguser_byrepresentitive(data: Dict[str, str]) -> Tuple[Dict[str, str], int]:
    res = permissionForTaguser.addTaguserPer_repre()
    if not res:
        return response_with(PERMISSION_ERROR_403, message='当前接口用于客户代表添加被测用户')
    return save_new_taguser(data)

@jwt_required()
def save_new_taguser_expRepre(data: Dict[str, str]) -> Tuple[Dict[str, str], int]:
    # 除日志管理员外，其他用户均可创建被测用户
    res = permissionForTaguser.addTaguserPer_expRespre()
    if not res:
        return response_with(PERMISSION_ERROR_403, message='日志管理员没有添加被测用户的权限或客户代表不通过该接口添加数据')
    return save_new_taguser(data)
    # taguser = targetUser.query.filter_by(email=data['email']).first()
    # sysuser = sysUser.query.filter_by(email=data['email']).first()
    # print('成功了吗')
    # if (not taguser) and (not sysuser):
    #     new_user = targetUser()
    #     # 判断用户是否输入用户名、锁定、冻结等参数
    #     new_data = check_input(request.json)
    #     wj2o(new_user, new_data)
    #     save_changes(new_user)
    #     return response_with(SUCCESS_201)
    # else:
    #     response_object = {
    #         'status': 'fail',
    #         'message': 'User already exists. Please Log in.',
    #     }
    #     return response_object, 409

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

def get_tagusers_byRole(id):
    sysuser = sysUser.query.filter_by(id=int(id)).first()
    if sysuser.sysrole == 'sysadmin':
        # 获取所有测试用户
        resData = targetUser.query.all()
    elif sysuser.sysrole == 'projectadmin':
        # 直接：当前项目管理员创建的被测用户
        # 间接：当前项目管理员创建的客户代表创建的被测用户
        # 其他：系统管理员创建的被测用户, 系统管理员创建的客户代表创建的被测用户
        sysIDs_list = getIDSofSysAdmin()
        repIDs_list = getRepresentitiveIDs_currentProjAdmin()
        repIDs_sysadmin_list = getRepreIDs_sysAdmin()
        IDs_List = repIDs_list+sysIDs_list+repIDs_sysadmin_list
        resData = targetUser.query.filter(or_(targetUser.createdbyuid==int(id), targetUser.createdbyuid.in_(IDs_List))).all()
    elif sysuser.sysrole == 'representative':
        # 对接人ID为当前客户代表的被测用户
        resData = targetUser.query.filter(targetUser.representativeID == int(id)).all()
    else:
        resData = []
    return resData

@jwt_required()
def get_all_tagusers():
    # 根据当前用户ID或系统角色进行判断
    # 系统管理员可以查看其下的所有用户（包括项目管理员、日志管理员、客户代表）
    print('返回的所有系统用户的数据类型',type(targetUser.query.all()))
    # return data by role
    id = get_jwt_identity()
    return get_tagusers_byRole(id=id)
    # return targetUser.query.all()

def get_all_tagusers_test():
    # 根据当前用户ID或系统角色进行判断
    # 系统管理员可以查看其下的所有用户（包括项目管理员、日志管理员、客户代表）
    print('返回的所有系统用户的数据类型',type(targetUser.query.all()))
    id = get_jwt_identity()

    return targetUser.query.all()


@jwt_required()
def get_a_taguser(id):
    # 权限：系统管理员、项目管理员、客户代表
    repIDs_list = getRepresentitiveIDs_currentProjAdmin()
    repIDs_sysadmin_list = getRepreIDs_sysAdmin()
    IDs = repIDs_list+repIDs_sysadmin_list
    res, taguser = permissionForTaguser.operationPerForATaguser(obj_id=id,IDs=IDs)
    if res==2:
        return response_with(PERMISSION_ERROR_403), 403
    elif res==0:
        return response_with(INVALID_INPUT_422), 422
    else:
        return taguser
    # return targetUser.query.filter_by(id=id).first()

def save_changes(data: targetUser) -> None:
    db.session.add(data)
    db.session.commit()

def get_sysusers_byRole_forsearch(id):
    sysuser = sysUser.query.filter_by(id=int(id)).first()
    if sysuser.sysrole == 'sysadmin':
        # 获取所有测试用户
        resData = targetUser.query
    elif sysuser.sysrole == 'projectadmin':
        # 直接：当前项目管理员创建的被测用户
        # 间接：当前项目管理员创建的客户代表创建的被测用户
        # 其他：系统管理员创建的被测用户, 系统管理员创建的客户代表创建的被测用户
        sysIDs_list = getIDSofSysAdmin()
        repIDs_list = getRepresentitiveIDs_currentProjAdmin()
        repIDs_sysadmin_list = getRepreIDs_sysAdmin()
        IDs_List = repIDs_list + sysIDs_list + repIDs_sysadmin_list
        resData = targetUser.query.filter(or_(targetUser.createdbyuid == int(id), targetUser.createdbyuid.in_(IDs_List)))
    elif sysuser.sysrole == 'representative':
        # 对接人ID为当前客户代表的被测用户
        resData = targetUser.query.filter(targetUser.representativeID == int(id))

    return resData

@jwt_required()
def search_for_tagusers(data):
    print('数据',data)
    id = get_jwt_identity()
    tmp_tagusers = get_sysusers_byRole_forsearch(id)
    if not tmp_tagusers:
        return response_with(ITEM_NOT_EXISTS)
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
            tmp_tagusers = tmp_tagusers.filter(targetUser.representativeID == int(data['representativeID']))
    except:
        print('无representativeID')
    try:
        if data['status_freeze']:
            tmp_tagusers = tmp_tagusers.filter(targetUser.isfreezed == True)
    except:
        print('无status_freeze')
    try:
        print('status_lock',data['status_lock'])
        if data['status_lock']:
            tmp_tagusers = tmp_tagusers.filter(targetUser.islocked == True)
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
    try:
        if data['comments']:
            tmp_tagusers = tmp_tagusers.filter(targetUser.comments.like("%" + data['comments'] + "%"))
    except:
        print('无comments')
    return tmp_tagusers.all(), 201

