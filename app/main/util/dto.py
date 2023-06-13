from flask_restx import Namespace, fields

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

searchWordsIn = {
        'id': fields.Integer(required=False, description='id'),
        'partial_name': fields.String(required=False, description='name'),
        'create_time_start': CustomDate(required=False, dt_format='str_time', description='like topic mentioned'),
        'create_time_end': CustomDate(required=False, dt_format='str_time', description='like topic mentioned'),
        'modify_time_start': CustomDate(required=False, dt_format='str_time', description='like topic mentioned'),
        'modify_time_end': CustomDate(required=False, dt_format='str_time', description='like topic mentioned'),
        'status': fields.String(required=False, description='organization comments'),
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
    userOut = ns.model('userOut', {
        'id': fields.Integer(description='user id'),
        'email': fields.String(description='user email address'),
        'mobile': fields.String(description='user email address'),
        'telephone': fields.String(description='user email address'),
        'wechat_num': fields.String(description='user email address'),
        'telecom_num': fields.String(description='user email address'),
        'username': fields.String(description='user username'),
        'password': fields.String(description='user password'),
        'sysrole': fields.String(description='user role'),
        'orgid': fields.Integer(description='the organization id the user belonging to'),
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
    })


class AuthDTO:
    ns = Namespace('auth', description='authentication related operations')
    auth_dto = ns.model('auth_details', {
        'email': fields.String(required=True, description='The email address'),
        'password': fields.String(required=True, description='The user password '),
        # 'verify_code': fields.String(required=True, description='verify code string'),
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