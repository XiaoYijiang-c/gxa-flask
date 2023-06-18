from flask import request

from app.main import db
from app.main.model.user import User
from typing import Dict, Tuple
from flask_jwt_extended import create_access_token
from app.main.util.response_tip import *
from app.main.util.write_json_to_obj import wj2o

from flask_jwt_extended import get_jwt_identity, jwt_required
from datetime import datetime



def operate_a_user(id, operator):
    """
    操作包含：锁定|解锁、冻结|解冻、删除
    Args:
        id: user id
        operator:

    Returns:

    """
    tmp_user = User.query.filter_by(id=id).first()
    print(tmp_user.isfreezed)

    if not tmp_user:
        return response_with(ITEM_NOT_EXISTS)

    if tmp_user.isfreezed:
        # 用户被冻结，不能登录，也就不能进行相关操作，除解冻外，解冻还需检验操作对象权限
        # 暂不考虑操作权限
        print(operator)
        if operator != "unfreeze":
            print('进来这儿')
            return response_with(ITEM_FREEZED_400)
        else:
            tmp_user.isfreezed = False
    else:
        # 用户没有被冻结
        if operator == "freeze":
            tmp_user.isfreezed = True
        else:
            if tmp_user.islocked:
                if operator != "unlock":
                    return response_with(ITEM_LOCKED_400)
                else:
                    tmp_user.islocked = False
            else:
                if operator == "lock":
                    tmp_user.islocked = True
                elif operator == "delete":
                    db.session.delete(tmp_user)
                else:
                    print("日怪")
                    return response_with(INVALID_INPUT_422)
    # tmp_projects, http_code = get_projects_by_organization_id(tmp_organization.id)
    # operate_projects(tmp_projects, operator)
    db.session.commit()
    # 冻结用户时,其创建的用户会被冻结吗?
    detail = "正" + operator + "与当前组织相关的项目"
    print('这儿也进来啦？')
    return response_with(SUCCESS_201)

def operate_users(users, operator):
    for item in users:
        if item:
            try:
                operate_a_user(item.id, operator)
                db.session.commit()
            except Exception as e:
                print(f"组织{item.id}操作出错，操作符：{operator}".format())

@jwt_required()
def update_a_user(id):
    tmp_user = User.query.filter_by(id=id).first()
    if not tmp_user:
        return response_with(ITEM_NOT_EXISTS)
    if tmp_user.isfreezed == True:
        return response_with(ITEM_FREEZED_400)
    elif tmp_user.islocked == True:
        return response_with(ITEM_LOCKED_400)
    update_val = request.json
    update_val['modifiedbyuid'] = get_jwt_identity()
    update_val['modifiedtime'] = datetime.now()
    if ('password' in update_val.keys()) and (not update_val['password']):
        del update_val['password']
    wj2o(tmp_user, update_val)
    save_changes(tmp_user)
    response_object = {
        'code': 'success',
        'message': f'User {id} updated!'.format()
    }
    return response_object, 201

def save_new_user(data: Dict[str, str]) -> Tuple[Dict[str, str], int]:
    user = User.query.filter_by(email=data['email']).first()
    if not user:
        new_user = User()
        wj2o(new_user, request.json)
        save_changes(new_user)
        return generate_token(new_user)
    else:
        response_object = {
            'status': 'fail',
            'message': 'User already exists. Please Log in.',
        }
        return response_object, 409


def get_all_users():
    return User.query.all()


def get_a_user(id):
    return User.query.filter_by(id=id).first()


def generate_token(user: User) -> Tuple[Dict[str, str], int]:
    try:
        # generate the auth token
        response_object = {
            'status': 'success',
            'message': 'Successfully registered.',
            'Authorization': create_access_token(user.id)
        }
        return response_object, 201
    except Exception as e:
        response_object = {
            'status': 'fail',
            'message': 'Some error occurred. Please try again.' + str(e)
        }
        return response_object, 401


def get_users_by_org_id(id):
    users = User.query.filter_by(orgid=id).all()
    return users, 201


def save_changes(data: User) -> None:
    db.session.add(data)
    db.session.commit()


def search_for_users(data):
    tmp_users = User.query
    try:
        if data['id']:
            tmp_users = tmp_users.filter_by(id=int(data['id']))
    except:
        print('无id')
    try:
        print('过滤orgid')
        if data['orgid']:
            tmp_users = tmp_users.filter_by(orgid=int(data['orgid']))
    except:
        print('无orgid')
    try:
        if data['partial_name']:
            tmp_users = tmp_users.filter(User.username.like("%" + data['partial_name'] + "%"))
    except:
        print('无username')
    try:
        if data['createtime']:
            tmp_users = tmp_users.filter(User.createtime >= data['createtime'])
    except:
        print('无createtime')
    try:
        if data['lockedtime']:
            tmp_users = tmp_users.filter(User.lockedtime >= data['lockedtime'])
    except:
        print('无lockedtime')
    try:
        if data['freezedtime']:
            tmp_users = tmp_users.filter(User.freezetime >= data['freezedtime'])
    except:
        print('无freezedtime')
    try:
        if data['sysrole']:
            tmp_users = tmp_users.filter(User.sysrole.like("%" + data['sysrole'] + "%"))
    except:
        print('无sysrole')
    try:
        if data['status_freeze']:
            tmp_users = tmp_users.filter(User.isfreezed==True)
    except:
        print('无status_freeze')
    try:
        if data['status_lock']:
            tmp_users = tmp_users.filter(User.islocked==True)
    except:
        print('无status_lock')
    try:
        if data['position']:
            tmp_users = tmp_users.filter(User.position.like("%" + data['position'] + "%"))
    except:
        print('无position')
    # createdbyuid
    try:
        if data['createdbyuid']:
            tmp_users = tmp_users.filter_by(createdbyuid=int(data['createdbyuid']))
            print('查询结果',tmp_users)
    except:
        print('无createdbyuid')
    try:
        if data['freezedbyuid']:
            tmp_users = tmp_users.filter_by(freezedbyuid=int(data['freezedbyuid']))
    except:
        print('无freezedbyuid')
    try:
        if data['modifiedbyuid']:
            tmp_users = tmp_users.filter_by(modifiedbyuid=int(data['modifiedbyuid']))
    except:
        print('无modifiedbyuid')
    try:
        if data['lockedbyuid']:
            tmp_users = tmp_users.filter_by(createdbyuid=int(data['lockedbyuid']))
    except:
        print('无lockedbyuid')
    return tmp_users.all(), 201

