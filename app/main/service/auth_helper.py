from pprint import pprint

from flask import request, session
from flask_jwt_extended import create_access_token, create_refresh_token
from app.main.model.newuser import sysUser
from typing import Dict, Tuple
import random
import string
from PIL import Image, ImageFont, ImageDraw, ImageFilter
from io import BytesIO
from app.main.util.response_tip import *
from app.main import db, jwt


def rnd_color():
    """随机颜色"""
    return random.randint(32, 127), random.randint(32, 127), random.randint(32, 127)


def gen_text():
    """生成4位验证码"""
    return ''.join(random.sample(string.ascii_letters + string.digits, 4))


def draw_lines(draw, num, width, height):
    """划线"""
    for num in range(num):
        x1 = random.randint(0, width / 2)
        y1 = random.randint(0, height / 2)
        x2 = random.randint(0, width)
        y2 = random.randint(height / 2, height)
        draw.line(((x1, y1), (x2, y2)), fill='black', width=1)

# 更新图片验证码
def get_piccatch():
    image, code = Auth.generate_verify_code()
    # 图片以二进制形式写入
    buf = BytesIO()
    image.save(buf, 'jpeg')
    buf_str = buf.getvalue()
    # 把buf_str作为response返回前端，并设置首部字段
    response = make_response(buf_str)
    response.headers['Content-Type'] = 'image/gif'
    # 将验证码字符串储存在session中
    session['verify_code'] = code
    print("生成的验证码：", code)
    return response

from app.main.model.blacklist import  BlackList
from datetime import datetime
from flask_jwt_extended import get_jwt_identity, get_jti, decode_token, jwt_required


from app.main.util.ext import save_changes
# 将用户Token加入黑名单
def save_token(sysuser,token=None, comments=None):
    revoked_token = BlackList()
    if not token:
        jti = get_jti(sysuser.token)
    else:
        jti = get_jti(token)
    id = get_jwt_identity()
    entertime = datetime.now()
    createdbyuid = get_jwt_identity()
    new_data = {
        'jti': jti,
        'operatetime': entertime,
        'uid': sysuser.id,
        'createdbyuid': id,
        'comments':comments
    }
    print('字典数据',new_data)
    wj2o(revoked_token, new_data)
    save_changes(revoked_token)
    # revoked_token = BlackList(jti=jti, operatetime=entertime, uid=id, createdbyuid=createdbyuid)
    print('对象',revoked_token)

# 判断用户Token是否在黑名单中
def is_token_revoked(decoded_token):
    jti = decoded_token['jti']
    token = BlackList.query.filter_by(jti=jti).first()
    return token is not None
@jwt.token_in_blocklist_loader
def check_if_token_revoked(jwt_header, jwt_payload: dict) -> bool:
    jti = jwt_payload["jti"]
    token = BlackList.query.filter_by(jti=jti).first()
    return token is not None

from .. import flask_bcrypt
from app.main.util.write_json_to_obj import wj2o
from app.main.service.sysuser_services import save_changes
class Auth:
    @staticmethod
    def generate_verify_code():
        """生成验证码图形"""
        code = gen_text()
        # 图片大小120×50
        width, height = 120, 50
        # 新图片对象
        img = Image.new('RGB', (width, height), 'white')
        # 字体
        font = ImageFont.truetype('app/static/arial.ttf', 40)
        # draw对象
        draw = ImageDraw.Draw(img)
        # 绘制字符串
        for item in range(4):
            draw.text((5 + random.randint(-3, 3) + 23 * item, 5 + random.randint(-3, 3)),
                      text=code[item], fill=rnd_color(), font=font)
        # 划线
        draw_lines(draw, 2, width, height)
        # 高斯模糊
        img = img.filter(ImageFilter.GaussianBlur(radius=1.5))
        return img, code

    @staticmethod
    def login_user(data: Dict[str, str]) -> Tuple[Dict[str, str], int]:
        try:
            print('登录入口')
            pprint(request.cookies)
            pprint(request.json)
            print("获取的生成的验证码：", session['verify_code'], ":", "发送来的验证码：", request.json['verify_code'])

            if session['verify_code'] != request.json['verify_code']:
                response_object = {
                    'status': 'fail',
                    'message': 'verify code error',
                }
                # 更新图片验证码
                response = get_piccatch()
                # return response
                return response_object, 403

            # fetch the user data
            user = sysUser.query.filter_by(email=data.get('email')).first()
            print('查询到的用户',user)
            passwd = data.get('password')
            print('用户密码对应的散列值',flask_bcrypt.generate_password_hash(passwd).decode('utf-8'))
            print(user.check_password(data.get('password')),  user.isfreezed)
            if user and user.check_password(data.get('password')) and (not user.isfreezed):
                # 增加额外声明
                additional_claims = {'sysrole': user.sysrole}
                auth_token = create_access_token(user.id, fresh=True, additional_claims=additional_claims)
                refresh_token = create_refresh_token(user.id)
                if auth_token:
                    # 更新用户Token字段
                    update_val = {"token": auth_token}
                    wj2o(user, update_val)
                    save_changes(user)
                    response_object = {
                        'status': 'success',
                        'message': 'Successfully logged in.',
                        'Authorization': auth_token
                    }
                    # 更新图片验证码
                    response = get_piccatch()
                    return response_object, 200
            else:
                response_object = {
                    'status': 'fail',
                    'message': 'email or password does not match.'
                }
                # 更新图片验证码
                response = get_piccatch()
                return response_object, 401

        except Exception as e:
            # 更新图片验证码
            response = get_piccatch()
            print('状态码500出错',e)
            response_object = {
                'status': 'fail',
                'message': 'Try again'
            }
            return response_object, 500

    @staticmethod
    @jwt_required()
    def logout_user(data: str) -> Tuple[Dict[str, str], int]:
        if data:
            auth_token = data.split(" ")[1]
        else:
            auth_token = ''
        if auth_token:
            resp = decode_token(auth_token)
            print('这是自己自带的？',resp)
            if not isinstance(resp, str):
                # mark the token as blacklisted
                id = get_jwt_identity()
                sysuser = sysUser.query.filter_by(id=id).first()
                save_token(sysuser=sysuser, token=auth_token)
                response_object = {
                    'status': 'sucess',
                    'message': resp
                }
                return response_object, 200
            else:
                response_object = {
                    'status': 'fail',
                    'message': resp
                }
                return response_object, 401
        else:
            response_object = {
                'status': 'fail',
                'message': 'Provide a valid auth token.'
            }
            return response_object, 403


