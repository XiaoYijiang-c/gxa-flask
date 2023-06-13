from datetime import datetime
from flask import request
from app.main import db
from app.main.model.organization import Organization
from typing import Dict, Tuple
from flask_jwt_extended import get_jwt_identity, jwt_required

from app.main.model.user import User
from app.main.util.response_tip import *
from app.main.util.write_json_to_obj import wj2o


@jwt_required()
def save_new_organization(data: Dict[str, str]) -> Tuple[Dict[str, str], int]:
    organization = Organization.query.filter_by(name= data['name']).first()
    if not organization:
        new_organization = Organization()
        data = request.json
        data['createdbyuid'] = get_jwt_identity()
        wj2o(new_organization, data)
        save_changes(new_organization)
        return response_with(SUCCESS_201)
    else:
        response_object = {
            'status': 'fail',
            'message': 'Organization already exists.',
        }
        return response_object, 409


def get_an_organization(id):
    return Organization.query.filter_by(id=id).first(), 201

def get_all_organizations():
    return Organization.query.all(), 201

# TODO
def search_for_organizations(data):
    tmp_orgs = Organization.query
    try:
        if data['id']:
            print(data['id'])
            tmp_orgs = tmp_orgs.filter_by(id = data['id'])
    except:
        print("无id")

    try:
        if data['partial_name']:
            tmp_orgs = tmp_orgs.filter(Organization.name.like("%" + data['partial_name'] + "%"))
    except:
        print("无name")

    try:
        if data['create_time_start'] and data['create_time_end']:
            tmp_orgs = tmp_orgs.filter(Organization.createtime.between(data['create_time_start'], data['create_time_end']))
            print(tmp_orgs.all())
    except Exception as e:
        print("无create", e)

    try:
        if data['modify_time_start'] and data['modify_time_end']:
            tmp_orgs = tmp_orgs.filter(Organization.modifytime.between(data['modify_time_start'], data['modify_time_end']))
    except:
        print("无modi")

    try:
        if data['status']:
            tmp_orgs = tmp_orgs.filter_by(status = data['status'])
    except:
        print("无status")

    print(tmp_orgs.all())
    return tmp_orgs.all(), 201




@jwt_required()
def update_an_organization(id):
    tmp_organization = Organization.query.filter_by(id=id).first()
    if not tmp_organization:
        return response_with(ITEM_NOT_EXISTS)
    if tmp_organization.islocked == True:
        return response_with(ITEM_LOCKED_400)
    update_val = request.json
    update_val['lastmodifiedbyuid'] = get_jwt_identity()
    update_val['lastmodifiedtime'] = datetime.now()
    wj2o(tmp_organization, update_val)
    save_changes(tmp_organization)
    response_object = {
        'code': 'success',
        'message': f'Organization {id} updated!'.format()
    }
    return response_object, 201

# TODO:提升健壮性，避免改变状态后后续操作失败，导致状态不一致
def operate_an_organization(id, operator):
    """
    操作包含：锁定|解锁、暂停|恢复、冻结|解冻、删除
    Args:
        id: organization id
        operator:

    Returns:

    """
    tmp_organization = Organization.query.filter_by(id=id).first()

    if not tmp_organization:
        return response_with(ITEM_NOT_EXISTS)
    if tmp_organization.islocked:
        if operator != "unlock":
            return response_with(ITEM_LOCKED_400)
        else:
            tmp_organization.islocked = False
    else:
        if operator == "lock":
            tmp_organization.islocked = True
        elif operator == "delete":
            db.session.delete(tmp_organization)
        else:
            print("日怪")
            return response_with(INVALID_INPUT_422)
    tmp_projects, http_code = get_projects_by_organization_id(tmp_organization.id)
    operate_projects(tmp_projects, operator)
    db.session.commit()
    return response_with(SUCCESS_201)


def operate_organizations(organizations, operator):
    for item in organizations:
        if item:
            try:
                operate_an_organization(item.id, operator)
                db.session.commit()
            except Exception as e:
                print(f"组织{item.id}操作出错，操作符：{operator}".format())


def get_sub_organizations(higher_organization_id):
    tmp_orgs = Organization.query.filter_by(higherorgid=higher_organization_id).all()
    return tmp_orgs, 201

def get_parent_organization(child_organization_id):
    current_org = Organization.query.filter_by(id=child_organization_id).first()
    higher_org_id = current_org.higherorgid
    higher_org = Organization.query.filter_by(id=higher_org_id).first()
    return higher_org, 201

def get_org_by_user_id(uid):
    print(1)
    orgid = User.query.filter_by(id=uid).first().orgid
    print(orgid)
    return Organization.query.filter_by(id=orgid).first(), 201


def save_changes(data: Organization) -> None:
    db.session.add(data)
    db.session.commit()

