from flask import request

from app.main import db
from app.main.model.user import User
from typing import Dict, Tuple
from flask_jwt_extended import create_access_token
from ..util.write_json_to_obj import wj2o


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
