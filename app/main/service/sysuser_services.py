from flask import request

from app.main import db
from app.main.model.newuser import sysUser, targetUser
from typing import Dict, Tuple
from flask_jwt_extended import create_access_token
from app.main.util.response_tip import *
from app.main.util.write_json_to_obj import wj2o

from flask_jwt_extended import get_jwt_identity, jwt_required
from datetime import datetime


from app.main.service.auth_helper import save_token
from sqlalchemy import or_, and_, not_, exists, select

def getIDSofSysAdmin():
    IDs = sysUser.query.filter(sysUser.sysrole == 'sysadmin').with_entities(sysUser.id).all()
    IDs_list = [ID[0] for ID in IDs]
    return IDs_list

# 获取系统用户创建的客户代表的ID集合
def getRepreIDs_sysAdmin():
    sysadminIDs = getIDSofSysAdmin()
    IDs = sysUser.query.filter(and_(sysUser.sysrole == 'representative', sysUser.createdbyuid.in_(sysadminIDs))).with_entities(sysUser.id).all()
    IDs_list = [ID[0] for ID in IDs]
    return IDs_list
def add_to_blacklist(tmp_sysuser):
    # 如用户被删除，则将其Token加入黑名单
    print('Token', tmp_sysuser.token)
    save_token(tmp_sysuser)



def operate_a_sysuser_func(tmp_sysuser,operator):
    """
        操作包含：锁定|解锁、冻结|解冻、删除
        Args:
            id: user id
            operator:

        Returns:

        """
    # tmp_sysuser = sysUser.query.filter_by(id=id).first()
    if not tmp_sysuser:
        return response_with(ITEM_NOT_EXISTS, message='用户不存在')
    if tmp_sysuser.isfreezed:
        # 用户被冻结，不能登录，也就不能进行相关操作，除解冻外，解冻还需检验操作对象权限
        # 暂不考虑操作权限
        if operator != "unfreeze":
            if operator == 'freeze':
                pass
            else:
                return response_with(ITEM_FREEZED_400, message=str(tmp_sysuser.username)+'已被冻结')
        else:
            tmp_sysuser.isfreezed = False
    else:
        # 用户没有被冻结
        if operator == "freeze":
            print('进来冻结')
            tmp_sysuser.isfreezed = True
            tmp_sysuser.freezetime = datetime.now()
            # 用户被冻结后需要将其Token加入黑名单
            add_to_blacklist(tmp_sysuser)
        else:
            if tmp_sysuser.islocked:
                if operator != "unlock":
                    if operator == 'lock':
                        pass
                    else:
                        return response_with(ITEM_LOCKED_400)
                else:
                    tmp_sysuser.islocked = False
            else:
                if operator == "lock":
                    tmp_sysuser.islocked = True
                    tmp_sysuser.lockedtime = datetime.now()
                elif operator == "delete":
                    db.session.delete(tmp_sysuser)
                    # 用户被冻结后需要将其Token加入黑名单
                    add_to_blacklist(tmp_sysuser)
                elif operator == "unlock":
                    pass
                else:
                    return response_with(INVALID_INPUT_422)
    tmp_sysuser.modifiedbyuid = get_jwt_identity()
    tmp_sysuser.modifiedtime = datetime.now()
    return response_with(SUCCESS_201)

@jwt_required()
def operate_a_sysuser(id, operator):
    IDsList = getIDSofSysAdmin()
    res, tmp_sysuser = permission.getSysuserPer(id, IDsList=IDsList)
    print('权限执行结果', res)
    if res == 2:
        return response_with(PERMISSION_ERROR_403, message='没有该操作权限'), 403
    elif res == 0:
        return response_with(INVALID_INPUT_422, message='输入内容无效'), 422
    else:
        resp = operate_a_sysuser_func(tmp_sysuser,operator=operator)
        resbody = resp.data.decode('utf-8')
        resbody = eval(resbody)
        if resbody['status'] == 'success':
            db.session.commit()
        return resp


@jwt_required()
def operate_sysusers(IDs, operator):
    IDsList = getIDSofSysAdmin()
    res, respData = permission.getSysusersPer(IDs, IDsList=IDsList)
    print('权限执行结果', res)
    if res == 2:
        return response_with(PERMISSION_ERROR_403, message='对'+str(respData)+'没有该操作权限'), 403
    elif res == 0:
        return response_with(SERVER_ERROR_500, message='请再试一次')
    else:
        for tmp_sysuser in respData:
            try:
                tmp_sysuser
                resp = operate_a_sysuser_func(tmp_sysuser, operator)
                resbody = resp.data.decode('utf-8')
                resbody = eval(resbody)
                if resbody['status'] != 'success':
                    return resp
                # db.session.commit()
            except Exception as e:
                error = f"系统用户{tmp_sysuser.username}操作出错，操作符：{operator}".format()
                print(error)
                return response_with(error=error)
        db.session.commit()
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
    IDsList = getIDSofSysAdmin()
    res, tmp_sysuser = permission.getSysuserPer(id, IDsList=IDsList)
    print('权限结果', res)
    if res == 2:
        return response_with(PERMISSION_ERROR_403, message='没有该操作权限'), 403
    elif res == 0:
        return response_with(INVALID_INPUT_422, message='输入内容无效'), 422
    else:
        # tmp_sysuser = sysUser.query.filter_by(id=id).first()
        if not tmp_sysuser:
            return response_with(ITEM_NOT_EXISTS, message='用户不存在')
        if tmp_sysuser.isfreezed == True:
            return response_with(ITEM_FREEZED_400, message='用户被冻结')
        elif tmp_sysuser.islocked == True:
            return response_with(ITEM_LOCKED_400, message='用户被锁住')
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
        db.session.commit()
        response_object = {
            'code': 'success',
            'message': f'User {id} updated!'.format()
        }
        return response_object, 201

# 验证相应字段
def check_input(inputData):
    if ('username' not in inputData.keys()) or (not inputData['username']):
        # 将用户邮箱默认为用户名
        inputData['username'] = inputData['email']
    if ('islocked' in inputData.keys()):
        inputData['lockedtime'] = datetime.now()
        inputData['lockedbyuid'] = get_jwt_identity()
        print('get_jwt_identity()',get_jwt_identity())
    if ('isfreezed' in inputData.keys()):
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

from app.main.util.permission import permission
@jwt_required()
def save_new_sysuser(data: Dict[str, str]) -> Tuple[Dict[str, str], int]:
    # 先转换用户角色
    request.json['sysrole'] = role_change(request.json['sysrole'])
    # 先进行权限管理
    # 只有系统管理员和项目管理员可添加系统用户，传当前用户ID与需增加的用户的角色
    res = permission.addSysuserPer(request.json['sysrole'])
    print('权限结果',res)
    if res==2:
        # response_object = {
        #     'status': 'fail',
        #     'message': 'you have no permission',
        # }
        # return response_object, 403
        return response_with(PERMISSION_ERROR_403)
    elif res==0:
        return response_with(INVALID_INPUT_422)
    sysuser = sysUser.query.filter_by(email=data['email']).first()
    taguser = targetUser.query.filter_by(email=data['email']).first()
    if (not sysuser) and (not taguser):
        new_user = sysUser()
        # 判断用户是否输入用户名、锁定、冻结等参数
        new_data = check_input(request.json)
        print('添加数据',new_data)
        wj2o(new_user, new_data)
        save_changes(new_user)
        resp_obj, status = generate_token(new_user)
        # 更新用户Token字段
        token = resp_obj['Authorization']
        update_val = {"token":token}
        wj2o(new_user, update_val)
        db.session.commit()
        return resp_obj, status
    else:
        response_object = {
            'status': 'fail',
            'message': 'User already exists. Please Log in.',
        }
        return response_object, 409

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
    sysuser = sysUser.query.filter_by(id=id).first()
    if sysuser.sysrole == 'sysadmin':
        # 返回所有系统用户数据，除 非其创建的系统用户外
        resList = sysUser.query.filter(and_(sysUser.createdbyuid!=0,or_(sysUser.createdbyuid==id, sysUser.sysrole!='sysadmin'))).all()
        # resList = sysUser.query.all()
    elif sysuser.sysrole == 'projectadmin':
        # 返回系统创建的客户代表和当前项目管理员创建的客户代表
        # 获取所有系统用户的ID
        IDs_list = getIDSofSysAdmin()
        resList = sysUser.query.filter(or_(and_(sysUser.createdbyuid==id, sysUser.sysrole=='representative'), and_(sysUser.createdbyuid.in_(IDs_list), sysUser.sysrole=='representative'))).all()
    else:
        resList = []
    return resList

@jwt_required()
def get_all_sysusers():
    # 只有系统管理员和项目管理员可查看到系统用户信息
    print('返回的所有系统用户的数据类型',type(sysUser.query.all()))
    id = get_jwt_identity()
    return get_sysusers_byRole(id=id)
    # return sysUser.query.all()

@jwt_required()
def get_all_sysusers_test():
    # 根据当前用户ID或系统角色进行判断
    # 系统管理员可以查看其下的所有用户（包括项目管理员、日志管理员、客户代表）
    print('返回的所有系统用户的数据类型',type(sysUser.query.all()))
    id = get_jwt_identity()
    return get_sysusers_byRole(id=id)


@jwt_required()
def get_a_sysuser(id):
    # 权限控制，只有系统用户和创建该用户的系统用户才有权限
    IDsList = getIDSofSysAdmin()
    res, sysuser = permission.getSysuserPer(id, IDsList=IDsList)
    if res==2:
        return response_with(PERMISSION_ERROR_403), 403
    elif res==0:
        return response_with(INVALID_INPUT_422), 422
    else:
        return sysuser
    # sysuser = sysUser.query.filter_by(id=id).first()
    # return sysuser


def generate_token(sysuser: sysUser) -> Tuple[Dict[str, str], int]:
    try:
        # generate the auth token
        # 添加额外声明
        additional_claims = {'sysrole':sysuser.sysrole}
        response_object = {
            'status': 'success',
            'message': 'Successfully registered.',
            'Authorization': create_access_token(sysuser.id, additional_claims=additional_claims)
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

def get_sysusers_byRole_forsearch(id):
    sysuser = sysUser.query.filter_by(id=id).first()
    if sysuser.sysrole == 'sysadmin':
        # 返回所有系统用户数据，除 非其创建的系统用户外
        resList = sysUser.query.filter(and_(sysUser.createdbyuid!=0,or_(sysUser.createdbyuid==id, sysUser.sysrole!='sysadmin')))
    elif sysuser.sysrole == 'projectadmin':
        # 返回系统创建的客户代表和当前项目管理员创建的客户代表
        # 获取所有系统用户的ID
        IDs_list = getIDSofSysAdmin()
        resList = sysUser.query.filter(or_(and_(sysUser.createdbyuid==id, sysUser.sysrole=='representative'), and_(sysUser.createdbyuid.in_(IDs_list), sysUser.sysrole=='representative')))
    return resList


@jwt_required()
def search_for_sysusers(data):
    print('数据',data)
    id = get_jwt_identity()
    tmp_sysusers = get_sysusers_byRole_forsearch(id=id)
    if not tmp_sysusers:
        return response_with(ITEM_NOT_EXISTS)
    # tmp_sysusers = sysUser.query
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
            data['sysrole'] = role_change(data['sysrole'])
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
    try:
        if data['comments']:
            data['comments'] = role_change(data['comments'])
            tmp_sysusers = tmp_sysusers.filter(sysUser.comments.like("%" + data['comments'] + "%"))
    except:
        print('无comments')
    return tmp_sysusers.all(), 201

