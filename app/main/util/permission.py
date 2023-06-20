from flask_jwt_extended import get_jwt_identity, get_jwt
from app.main.model.newuser import sysUser, targetUser
from app.main.model.tricksituation import trickSituation


def util_sysUserPer(get_id, IDsList, sysrole, id):
    try:
        print('角色', sysrole)
        get_sysuser = sysUser.query.filter_by(id=int(get_id)).first()
        if sysrole == 'sysadmin' or (((get_sysuser.createdbyuid in IDsList and get_sysuser.sysrole == 'representative') or get_sysuser.createdbyuid == id) and sysrole == 'projectadmin'):
            return 1, get_sysuser
        else:
            return 2, None
    except:
        return 0, None

class permission:
    # 进行权限认证，根据用户角色返回相应的值
    # 系统管理员权限最高返回1
    @staticmethod
    def addSysuserPer(add_sysrole):
        try:
            sysrole = get_jwt().get('sysrole')
            print('当前用户角色',sysrole)
            if sysrole=='sysadmin':
                print('系统用户')
                return 1
            elif sysrole=='projectadmin' and add_sysrole=='representative':
                return 1
            else:
                return 2
        except:
            return 0

    @staticmethod
    def getSysuserPer(get_id, IDsList):
        # 获取目标用户的上级ID
        id = get_jwt_identity()
        sysrole = get_jwt().get('sysrole')
        return util_sysUserPer(get_id, IDsList, sysrole=sysrole, id=id)

    @staticmethod
    def getSysusersPer(get_ids, IDsList):
        id = get_jwt_identity()
        sysrole = get_jwt().get('sysrole')
        sysuserList = []
        for get_id in get_ids:
            res, sysuser = util_sysUserPer(get_id, IDsList, sysrole=sysrole, id=id)
            if res!=1:
                error_ids = get_id
                return res, error_ids
            else:
                sysuserList.append(sysuser)
        return 1, sysuserList

    @staticmethod
    def getblackListsPer():
        sysrole = get_jwt().get('sysrole')
        print('角色',sysrole)
        if sysrole=='sysadmin' or sysrole=='logadmin':
            return True
        else:
            return False

def utilPerForATaguser(obj_id, IDs, sysrole, id):
    print('进工具')
    try:
        taguser_obj = targetUser.query.filter_by(id=int(obj_id)).first()
        print('对象',taguser_obj, taguser_obj.createdbyuid)
        print('角色',sysrole, id)
        if sysrole == 'sysadmin':
            return 1, taguser_obj
        elif sysrole == 'projectadmin' and (taguser_obj.createdbyuid in IDs or taguser_obj.createdbyuid == id):
            return 1, taguser_obj
        elif sysrole == 'representative' and (taguser_obj.representativeID == id):
            print('进这儿')
            return 1, taguser_obj
        else:
            return 2, taguser_obj
    except:
        return 0, None

class permissionForTaguser:

    @staticmethod
    def addTaguserPer_expRespre():
        sysrole = get_jwt().get('sysrole')
        if sysrole == 'logadmin' or sysrole=='representative':
            return False
        else:
            return True

    @staticmethod
    def addTaguserPer_repre():
        sysrole = get_jwt().get('sysrole')
        if sysrole == 'representative':
            return True
        else:
            return False

    @staticmethod
    def operationPerForATaguser(obj_id, IDs):
        id = get_jwt_identity()
        sysrole = get_jwt().get('sysrole')
        return utilPerForATaguser(obj_id=obj_id, IDs=IDs, sysrole=sysrole, id=id)

    @staticmethod
    def operationPerForATagusers(obj_IDs, IDs):
        print('进来权限认证')
        id = get_jwt_identity()
        sysrole = get_jwt().get('sysrole')
        taguserList = []
        for obj_id in obj_IDs:
            print(obj_id, IDs)
            res, taguser = utilPerForATaguser(obj_id=obj_id, IDs=IDs, sysrole=sysrole, id=id)
            if res != 1:
                error_ids = obj_id
                return res, error_ids
            else:
                taguserList.append(taguser)
        return 1, taguserList
from sqlalchemy import or_
class permissionForTrickSituation:
    @staticmethod
    def getTrickSituationsPer(IDs_List):
        id = get_jwt_identity()
        sysrole = get_jwt().get('sysrole')
        try:
            if sysrole == 'sysadmin':
                # 获取所有测试用户
                resData = targetUser.query.with_entities(targetUser.id).all()
            elif sysrole == 'projectadmin':
                # 直接：当前项目管理员创建的被测用户
                # 间接：当前项目管理员创建的客户代表创建的被测用户
                # 其他：系统管理员创建的被测用户, 系统管理员创建的客户代表创建的被测用户
                resData = targetUser.query.filter(
                    or_(targetUser.createdbyuid == id, targetUser.createdbyuid.in_(IDs_List))).with_entities(targetUser.id).all()
            elif sysrole == 'representative':
                # 对接人ID为当前客户代表的被测用户
                resData = targetUser.query.filter(targetUser.representativeID == id).with_entities(targetUser.id).all()
            else:
                return 2, None
            IDs_list = [ID[0] for ID in resData]
            return 1, IDs_list
        except:
            0, None
