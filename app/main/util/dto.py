from flask_restx import Namespace, fields

####################@@@@@@@@@@@@自定义fields字段@@@@@@@@@@@@@@@@@@@@@@#######################
CustomDate = fields.DateTime

class CustomDate(fields.DateTime):
    '''
    自定义CustomDate,原有的fileds.DateTime序列化后
    只支持 rfc822,ios8601 格式，新增 strftime 格式
    strftime格式下支持 format 参数，默认为 '%Y-%m-%d %H:%M:%S'
    '''

    def __init__(self, dt_format='rfc822', format=None, **kwargs):
        super().__init__(**kwargs)
        self.dt_format = dt_format

    def format(self, value):
        if self.dt_format in ('rfc822', 'iso8601'):
            return super().format(value)
        elif self.dt_format == 'str_time':
            if isinstance(value, str):
                return value
            return value.strftime('%Y-%m-%d %H:%M:%S')

        else:
            raise Exception('Unsupported date format %s' % self.dt_format)

class Roleout(fields.Raw):
    def format(self, value):
        res = ''
        if value == 'sysadmin':
            res = '系统管理员'
        elif value == 'logadmin':
            res = '日志管理员'
        elif value == 'projectadmin':
            res = '项目管理员'
        else:
            res = '客户代表'
        return res
# class RoleIn(fields.String):
#     def format(self, value):
#         res = ''
#         if value == '系统管理员':
#             print('进来啦')
#             res = 'sysadmin'
#         elif value == '日志管理员':
#             res = 'logadmin'
#         elif value == '项目管理员':
#             res = 'projectadmin'
#         else:
#             res = 'representative'
#         return res
class Statusout(fields.Raw):
    def format(self, value):
        res = ''
        if value == True:
            res = '是'
        else:
            res = '否'
        return res
class StatusIn(fields.Raw):
    def format(self, value):
        res = ''
        if value == '是':
            res = True
        else:
            res = False
        return res
class Int_to_str(fields.Raw):
    def format(self, value):
        return str(value)
class str_to_Int(fields.String):
    def format(self, value):
        res = value.isdecimal()
        if not res:
            raise ValueError({'error': '输入编号不是数字'})
        return int(value)

class id_to_name(fields.String):
    def format(self, value):
        print(value)
        return value.username
####################@@@@@@@@@@@@自定义fields字段@@@@@@@@@@@@@@@@@@@@@@#######################

############@@@@@@@@@@@@@@@@@@@@@自定义验证字段@@@@@@@@@@@@@@@@@@@@@@@##############
class RoleIn:
    def __init__(self, required=False):
        self.required = required

    def __call__(self, value):
        # 在这里进行需要的修改逻辑
        print('进来没哦')
        res = ''
        if value == '系统管理员':
            print('进来啦')
            res = 'sysadmin'
        elif value == '日志管理员':
            res = 'logadmin'
        elif value == '项目管理员':
            res = 'projectadmin'
        else:
            res = 'representative'
        modified_value = res
        return modified_value


def validate_sysrole(value):
    res = ''
    if value == '系统管理员':
        print('进来啦')
        res = 'sysadmin'
    elif value == '日志管理员':
        res = 'logadmin'
    elif value == '项目管理员':
        res = 'projectadmin'
    else:
        res = 'representative'
    return res

def validate_mobile(Phone):
    hmd = [134,135,136,137,138,139,150,151,152,157,158,159,182,183,184,187,188,147,178,
         130,131,132,155,156,185,186,145,176,179,133,153,180,181,189,177]#列表
    if Phone.isnumeric():#判断Phone是否全部都是数字字符
        if len(Phone) == 11:#判断手机号是否为11位
            if int(Phone[0:3]) in hmd:#如果输入的手机号前三位数字在列表中，则输出"是一个有效号码"
                return True
            else:#如果输入的手机号前三位数字不在列表中，则输出"不是有效运营商网段"
                raise ValueError({'error': (Phone, "不是有效运营商网段")})
        else:#如果手机号不是11位，则输出"号码位数不对！"
            raise ValueError({'error': (Phone, "号码位数不对！")})
    else:#如果输入的手机号字符串不全是数字，则输出"号码必须全是数字"
        raise ValueError({'error': (Phone, "手机号码必须全是数字")})
import re
def validate_email(value):
    print('进来验证邮箱')
    if not re.match(r"[^@]+@[^@]+\.[^@]+", value):
        raise ValueError("Invalid email address")
############@@@@@@@@@@@@@@@@@@@@@自定义验证字段@@@@@@@@@@@@@@@@@@@@@@@##############

searchWordsIn = {
        'id': fields.Integer(required=False, description='id'),
        'partial_name': fields.String(required=False, description='name'),
        'create_time_start': CustomDate(required=False, dt_format='str_time', description='like topic mentioned'),
        'create_time_end': CustomDate(required=False, dt_format='str_time', description='like topic mentioned'),
        'modify_time_start': CustomDate(required=False, dt_format='str_time', description='like topic mentioned'),
        'modify_time_end': CustomDate(required=False, dt_format='str_time', description='like topic mentioned'),
        'status': fields.String(required=False, description='organization comments'),
    }

searchWordsInUser = {
        'id': str_to_Int(required=False, description='id'),
        'partial_name': fields.String(required=False, description='username'),
        'email': fields.String(required=False, description='email'),
        'sysrole': fields.String(required=False, description='the of user'),
        'orgid': str_to_Int(required=False,description='organization user belonged'),
        'createdbyuid': str_to_Int(required=False,description='users created by createduid'),
        'freezedbyuid': str_to_Int(required=False,description='users freezed by freezedbyuid'),
        'modifiedbyuid': str_to_Int(required=False,description='users mofieded by modifiedbyuid'),
        'lockedbyuid': str_to_Int(required=False,description='users locked by lockedbyuid'),
        'createtime': CustomDate(required=False, dt_format='str_time', description='the time of creating user'),
        'lockedtime': CustomDate(required=False, dt_format='str_time', description='the time of locking user'),
        'freezedtime': CustomDate(required=False, dt_format='str_time', description='the time of freezing user'),
        'modifiedtime': CustomDate(required=False, dt_format='str_time', description='the time of freezing user'),
        'status_freeze': fields.Boolean(required=False, description='freezed or unfreezed'),
        'status_lock': fields.Boolean(required=False, description='locked or unlocked'),
        'position': fields.String(required=False, description='user position'),
        'comments': fields.String(required=False, description='comments about user'),
        'representativeID': fields.String(required=False,description='users managed by managerID'),
    }

IDsIn = {
    'data': fields.List(fields.Integer, required=True, description='提供多个编号，列表类型'),
    }

class OrganizationDTO:
    ns = Namespace('organization', description='organization related operations')

    organizationIDsIn = ns.model('organizationIDsIn', IDsIn)

    organizationIn = ns.model('organizationIn', {
        'name': fields.String(required=True, description='organization name'),
        'logopath': fields.String(required=True, default="N/A",description='organization logo\'s file path'),
        'istoporg': fields.Boolean(required=True, default=False, description='is it a top organization'),
        'higherorgid': fields.Integer(required=True, description='higher organization id'),
        'islocked': fields.Boolean(required=True, default=False,description='can organization be modified'),
        'comments': fields.String(required=True, description='organization comments'),
    }, strict=True)

    organizationOut = ns.model('organizationOut', {
        'id': fields.Integer(description='organization id'),
        'name': fields.String(description='organization name'),
        'logopath': fields.String(description='organization logo\'s file path'),
        'istoporg': fields.Boolean(description='is it a top organization'),
        'higherorgid': fields.Integer(description='organization id'),
        'islocked': fields.Boolean(description='can organization be modified'),
        'createtime': CustomDate(required=True, description='the time when the organization created'),
        'modifytime': CustomDate(required=False, dt_format='str_time', description='like topic mentioned'),
        'comments': fields.String(description='organization comments'),
    })

    searchWordsIn = ns.model('searchIn', searchWordsIn)


class UserDTO:
    ns = Namespace('user', description='user related operations')

    userIDsIn = ns.model('userIDsIn', IDsIn)

    userOut = ns.model('userOut', {
        'id': fields.Integer(description='user id'),
        'email': fields.String(description='user email address'),
        'mobile': fields.String(description='user email address'),
        'telephone': fields.String(description='user email address'),
        'wechat_num': fields.String(description='user email address'),
        'telecom_num': fields.String(description='user email address'),
        'username': fields.String(description='user username'),
        # 'password': fields.String(description='user password'),
        'sysrole': fields.String(description='user role'),
        'orgid': fields.Integer(description='the organization id the user belonging to'),
        'createdbyuid': fields.Integer(description='the user id who create current user')
    })

    userIn = ns.model('userIn', {
        'email': fields.String(description='user email address'),
        'mobile': fields.String(description='user email address'),
        'telephone': fields.String(description='user email address'),
        'wechat_num': fields.String(description='user email address'),
        'telecom_num': fields.String(description='user email address'),
        'username': fields.String(description='user username'),
        'password': fields.String(description='user password'),
        'sysrole': fields.String(description='user role'),
        'orgid': fields.Integer(description='the organization id the user belonging to'),
        "position": fields.String(description='user position')
    })

    searchWordsIn = ns.model('searchIn', searchWordsInUser)
    operateIn = ns.model('operateIn', {
        "operate": fields.String(required=True, description='delete, lock|unlock, freeze|unfreeze')
    })


########系统用户###############################

class SysUserDTO:
    ns = Namespace('sysUser', description='sysUser related operations')

    userIDsIn = ns.model('userIDsIn', IDsIn)

    sysuserOut = ns.model('sysuserOut', {
        'id': fields.Integer(description='user id'),
        'username': fields.String(description='user username'),
        'email': fields.String(description='user email address'),
        'sysrole': Roleout(description='user role'),
        'createtime': CustomDate(dt_format='str_time', description='the time of creating user'),
        'createdbyuid': Int_to_str(description='the user id who create user'),
        'createusername': id_to_name(attribute='create_user', description='the user name who create user'),
        'mobile': fields.String(description='user mobile'),
        'comments': fields.String(description='comments about the user'),
        'islocked': fields.Boolean(description='whether user is locked'),
        'lockedbyuid': Int_to_str(description='the user id who lock user'),
        'lockeusername': id_to_name(attribute='lock_user', description='the user name who lock user'),
        'lockedtime': CustomDate(dt_format='str_time', description='the time of locking user'),
        'isfreezed': fields.Boolean(description='whether user is freezed'),
        'freezedbyuid': Int_to_str(description='the user id who freeze user'),
        'freezedusername': id_to_name(attribute='freeze_user', description='the user name who freeze user'),
        'freezetime': CustomDate(dt_format='str_time', description='the time of freezing user'),
        'modifiedbyuid': Int_to_str(description='the user id who modify user'),
        'modifyusername': id_to_name(attribute='modify_user', description='the user name who modify user'),
        'modifiedtime': CustomDate(dt_format='str_time', description='the time of modifying user')
    })

    # 输入内容需要进行验证的有：系统角色、手机号、email
    sysuserIn = ns.model('userIn', {
        'email': fields.String(required=True, validate=validate_email, description='user email address'),
        'password': fields.String(required=True, description='user password'),
        'sysrole': fields.String(required=True, validate=RoleIn(), description='user role'),
        # 'sysrole': fields.String(required=True, validate=validate_sysrole, description='user role'),
        'mobile': fields.String(validate=validate_mobile, description='user email address'),
        'username': fields.String(description='user username'),
        'comments': fields.String(description='comments about the user'),
        'islocked': fields.Boolean(default=False, description='whether user is locked'),
        'isfreezed': fields.Boolean(default=False, description='whether user is freezed'),
    }, strict=True)

    # 编辑系统用户时的输入，除ID、外键和创建时间外都可以修改
    sysuserInUpdate = ns.model('userInUpdate', {
        'email': fields.String(validate=validate_email, description='user email address'),
        'password': fields.String(description='user password'),
        'sysrole': fields.String(validate=RoleIn(), description='user role'),
        'mobile': fields.String(validate=validate_mobile, description='user email address'),
        'username': fields.String(description='user username'),
        'comments': fields.String(description='comments about the user'),
        'islocked': fields.Boolean(default=False, description='whether user is locked'),
        'isfreezed': fields.Boolean(default=False, description='whether user is freezed'),
    }, strict=True)

    searchWordsIn = ns.model('searchIn', searchWordsInUser)

    operateIn = ns.model('operateIn', {
        "operate": fields.String(required=True, description='delete, lock|unlock, freeze|unfreeze')
    })
########系统用户###############################
class TagUserDTO:
    ns = Namespace('tagUser', description='sysUser related operations')

    userIDsIn = ns.model('userIDsIn', IDsIn)

    taguserOut = ns.model('taguserOut', {
        'id': fields.Integer(description='user id'),
        'username': fields.String(description='user username'),
        'email': fields.String(description='user email address'),
        'orgid': fields.String(description='the orgid which user belongs to'),
        'position': fields.String(description='user position'),
        'createtime': CustomDate(dt_format='str_time', description='the time of creating user'),
        'createdbyuid': Int_to_str(description='the user id who create user'),
        'createusername': id_to_name(attribute='create_sysuser', description='the user name who create user'),
        'mobile': fields.String(description='user mobile'),
        'telephone': fields.String(description='user email address'),
        'wechat_num': fields.String(description='user email address'),
        'telecom_num': fields.String(description='user email address'),
        'comments': fields.String(description='comments about the user'),
        'islocked': fields.Boolean(description='whether user is locked'),
        'lockedbyuid': Int_to_str(description='the user id who lock user'),
        'lockusername': id_to_name(attribute='locke_sysuser', description='the user name who lock user'),
        'lockedtime': CustomDate(dt_format='str_time', description='the time of locking user'),
        'isfreezed': fields.Boolean(description='whether user is freezed'),
        'freezedbyuid': Int_to_str(description='the user id who freeze user'),
        'freezeusername': id_to_name(attribute='freeze_sysuser', description='the user name who freeze user'),
        'freezetime': CustomDate(dt_format='str_time', description='the time of freezing user'),
        'modifiedbyuid': Int_to_str(description='the user id who modify user'),
        'modifyusername': id_to_name(attribute='modify_sysuser', description='the user name who modify user'),
        'modifiedtime': CustomDate(dt_format='str_time', description='the time of modifying user'),
        'representativeID': fields.String(description='the representitive id which user belongs to'),
        'representativeusername': id_to_name(attribute='representative_sysuser', description='the user name who is the user representitive'),
    })

    # 输入内容需要进行验证的有：系统角色、手机号、email
    taguserIn_sysadmin = ns.model('taguserIn_sysadmin', {
        'email': fields.String(required=True, validate=validate_email, description='user email address'),
        'username': fields.String(required=True, description='user username'),
        'orgid': fields.String(required=True, description='the orgid which user belongs to'),
        'position': fields.String(required=True, description='user position'),
        'representativeID': fields.String(required=True, description='the representitive id which user belongs to'),
        'mobile': fields.String(validate=validate_mobile, description='user email address'),
        'telephone': fields.String(description='user email address'),
        'wechat_num': fields.String(description='user email address'),
        'telecom_num': fields.String(description='user email address'),
        'comments': fields.String(description='comments about the user'),
        'islocked': fields.Boolean(default=False, description='whether user is locked'),
        'isfreezed': fields.Boolean(default=False, description='whether user is freezed'),
    }, strict=True)

    taguserIn_representitive = ns.model('taguserIn_representitive', {
        'email': fields.String(required=True, validate=validate_email, description='user email address'),
        'username': fields.String(required=True, description='user username'),
        'orgid': fields.String(required=True, description='the orgid which user belongs to'),
        'position': fields.String(required=True, description='user position'),
        'mobile': fields.String(validate=validate_mobile, description='user email address'),
        'telephone': fields.String(description='user email address'),
        'wechat_num': fields.String(description='user email address'),
        'telecom_num': fields.String(description='user email address'),
        'comments': fields.String(description='comments about the user'),
        'islocked': fields.Boolean(default=False, description='whether user is locked'),
        'isfreezed': fields.Boolean(default=False, description='whether user is freezed'),
    }, strict=True)

    # 编辑系统用户时的输入，除ID、外键和创建时间外都可以修改
    taguserInUpdate = ns.model('taguserInPute', {
        'email': fields.String(validate=validate_email, description='user email address'),
        'username': fields.String(description='user username'),
        'orgid': fields.String(description='the orgid which user belongs to'),
        'position': fields.String(description='user position'),
        'mobile': fields.String(validate=validate_mobile, description='user email address'),
        'telephone': fields.String(description='user email address'),
        'wechat_num': fields.String(description='user email address'),
        'telecom_num': fields.String(description='user email address'),
        'comments': fields.String(description='comments about the user'),
        'islocked': fields.Boolean(default=False, description='whether user is locked'),
        'isfreezed': fields.Boolean(default=False, description='whether user is freezed'),
        'representativeID': fields.String(description='the representitive id which user belongs to'),
    }, strict=True)
    searchWordsIn = ns.model('searchIn', searchWordsInUser)

    operateIn = ns.model('operateIn', {
        "operate": fields.String(required=True, description='delete, lock|unlock, freeze|unfreeze')
    })
#########被测用户###############################

##############黑名单###########################
class BlackListDTO:
    ns = Namespace('blasklist', description='blasklist related operations')
    blackListIn = ns.model('blaklistIn',{
        'uid': fields.String(required=True, description='the uid whose token will be add to blacklist'),
        'comments': fields.String(description='comments about the blacklist')
    }, strict=True)

    blackListOut = ns.model('blacklistOut',{
        'id': fields.Integer(description='blackList id'),
        'jti': fields.String(description='JWT TOKEN id'),
        'uid': fields.String(description='uid belongs the curretn Token'),
        'username': fields.String(description='username belongs the curretn Token'),
        'createdbyuid': fields.String(description='uid create the blacklist'),
        'createusername': fields.String(description='username  create the blacklist'),
        'operatetime': CustomDate(dt_format='str_time', description='the time of adding to blackList'),
        'comments': fields.String(description='comments about the blacklist'),
    })
    blackListIDsIn = ns.model('blackListIDsIn', IDsIn)
##############黑名单###########################

##############中招情况###########################
class trickSituationDTO:
    ns = Namespace('tricksituation', description='tricksituation related operations')
    trickSituationUpdate = ns.model('trickSituationUpdate',{
        'comments': fields.String(description='comments about the tricksituation')
    }, strict=True)
    trickSituationOut = ns.model('tricksituationOut', {
        'id': fields.Integer(description='tricksituation id'),
        'taguid': fields.String(description='related taguser id'),
        'username': fields.String(description='username belongs the curretn situation'),
        'taskid': fields.String(description='related task id'),
        'taskname': fields.String(description='related task name'),
        'tricktime': CustomDate(dt_format='str_time', description='the time of adding to tricksituation'),
        'action': fields.String(description='uid create the blacklist'),
        'inputContent': fields.String(description='the content user input'),
        'comments': fields.String(description='comments about the blacklist'),
    })

##############中招情况###########################


class AuthDTO:
    ns = Namespace('auth', description='authentication related operations')
    auth_dto = ns.model('auth_details', {
        'email': fields.String(required=True, description='The email address'),
        'password': fields.String(required=True, description='The user password '),
        'verify_code': fields.String(required=True, description='verify code string'),
    })


class ProjectDTO:
    ns = Namespace('project', description='project related operations')

    projectIDsIn = ns.model('projectIDsIn', IDsIn)

    searchWordsIn = ns.model('searchIn', searchWordsIn)

    projectOut = ns.model('projectOut', {
        'id': fields.Integer(description='project id'),
        'name': fields.String(required=True, description='project name'),
        'custoid': fields.String(required=True, description='the org which the project belongs to'),
        'owneruid': fields.Integer(required=True, description='the org which the project belongs to'),
        'createtime': CustomDate(required=True, description='the org which the project belongs to'),
        'createdbyuid': fields.Integer(required=True, description="the custom's organization who can manage the project"),
        'status': fields.String(required=True, description='project status'),
        'islocked': fields.Boolean(required=True, default=False, description='project status'),
        'comments': fields.String(required=True, description='project comments'),
        'lastmodifiedbyuid': fields.Integer(required=True, description='the last one who modified the project recently'),
        'lastmodifiedtime': CustomDate(required=True, description='the last time the project was recently modified'),
    })

    projectIn = ns.model('projectIn', {
        'name': fields.String(required=True, description='project name'),
        'custoid': fields.Integer(required=True, description='the org which the project belongs to'),
        'owneruid': fields.Integer(required=True, description='the org which the project belongs to'),
        'comments': fields.String(description='project comments'),
    })


class HTML_Template_DTO:
    ns = Namespace('template_html', description='html template related operations')

    html_templateIDsIn = ns.model('html_templateIDsIn', IDsIn)

    html_template_in = ns.model('html_template_in', {
        'type': fields.Integer(reqired=True, default=1, description='模板类型：如文本/html、二进制、office等'),
        'name': fields.String(reqired=True, default="1", description='模板名称;例：中石油-上级发文，xx局-入学通知，xx部门-人事任免公告等'),
        'subject': fields.String(reqired=True, default="1", description='邮件主题'),
        'content': fields.String(reqired=True, default="内容", description='邮件内容'),
        'attachid': fields.Integer(description='附件模板编号'),
        'islocked': fields.Boolean(description='是否锁定;锁定：不允许修改、删除。'),
        'ishidden': fields.Boolean(description='是否隐藏;隐藏：不可被选择使用'),
        'comments': fields.String(description='备注'),
    })

    html_template_out = ns.model('html_template_out', {
        'id': fields.Integer(description='html template id'),
        'type': fields.Integer(description='模板类型：如文本/html、二进制、office等'),
        'name': fields.String(description='模板名称;例：中石油-上级发文，xx局-入学通知，xx部门-人事任免公告等'),
        'subject': fields.String(description='邮件主题'),
        'content': fields.String(description='邮件内容'),
        'attachid': fields.Integer(description='附件模板编号'),
        'islocked': fields.Boolean(description='是否锁定;锁定：不允许修改、删除。'),
        'createtime': fields.DateTime(description='创建时间'),
        'createdbyuid': fields.Integer(description='创建人编号'),
        'lastmodifiedtime': fields.DateTime(description='修改时间'),
        'lastmodifiedbyuid': fields.Integer(description='修改人编号'),
        'ishidden': fields.Boolean(description='是否隐藏;不可被选择使用'),
        'comments': fields.String(description='备注'),
    })

    searchWordsIn = ns.model('searchIn', searchWordsIn)