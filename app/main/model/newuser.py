from app.main import db, flask_bcrypt
from datetime import datetime

class sysUser(db.Model):
    """
    系统用户：将对接人也算作系统用户
	用户名（可重复）、密码、emial(必填)、角色、创建时间、手机号、锁定、锁定时间、解锁时间、创建者编号、锁定者编号、冻结者编号、备注、ID
	"""
    """
        parent_id = db.Column(db.Integer, db.ForeignKey('account.id'), nullable=True, default=None)
        parent = db.relationship('Account', remote_side=[id], backref=db.backref('children', lazy='dynamic'))
        foreign_keys=[createdbyuid]
    """
    __tablename__ = 't_sysUser'
    __table_args__ = {'comment': '系统用户表'}
    id = db.Column(db.INTEGER, primary_key=True, comment='用户编号')
    username = db.Column(db.String(16), nullable=False, comment='用户名')
    email = db.Column(db.String(255), unique=True, nullable=False, comment='用户邮箱')
    password_hash = db.Column(db.String(100), comment='密码hash')
    sysrole = db.Column(db.Enum('sysadmin','logadmin','projectadmin','representative', name='role_type'), default='projectadmin', nullable=False,comment='系统角色：sysadmin | logadmin | projectadmin | representative')
    createtime = db.Column(db.DateTime, default=datetime.now(), nullable=False, comment='创建时间')
    createdbyuid = db.Column(db.INTEGER, db.ForeignKey('t_sysUser.id', name='fk_created_by_uid'), nullable=True, default=0,
                             comment='创建人的编号')
    create_user = db.relationship("sysUser", remote_side=[id], backref=db.backref('create_subusers', lazy='dynamic'), foreign_keys=[createdbyuid])
    mobile = db.Column(db.String(11), comment='用户手机号')
    comments = db.Column(db.Text(5120), comment='备注')
    islocked = db.Column(db.BOOLEAN, default=False, comment='是否锁定')
    lockedbyuid = db.Column(db.INTEGER, db.ForeignKey('t_sysUser.id', name='fk_locked_by_uid'), nullable=True, default=None, comment='锁定者编号')
    lock_user = db.relationship("sysUser", remote_side=[id], backref=db.backref('lock_subusers', lazy='dynamic'), foreign_keys=[lockedbyuid])
    lockedtime = db.Column(db.DateTime, comment='上锁时间')
    isfreezed = db.Column(db.BOOLEAN, default=False, comment='是否被冻结')
    freezedbyuid = db.Column(db.INTEGER, db.ForeignKey('t_sysUser.id', name='fk_freezed_by_uid'), nullable=True, default=None, comment='冻结者编号')
    freeze_user = db.relationship("sysUser", remote_side=[id], backref=db.backref('freeze_subusers', lazy='dynamic'), foreign_keys=[freezedbyuid])
    freezetime = db.Column(db.DateTime, comment='冻结时间')
    modifiedbyuid = db.Column(db.INTEGER, db.ForeignKey('t_sysUser.id', name='fk_modified_by_uid'), comment='修改者编号')
    modify_user = db.relationship("sysUser", remote_side=[id], backref=db.backref('modify_subusers', lazy='dynamic'), foreign_keys=[modifiedbyuid])
    modifiedtime = db.Column(db.DateTime, comment='最近一次修改时间')
    @property
    def password(self):
        raise AttributeError('password: write-only field')

    @password.setter
    def password(self, password):
        self.password_hash = flask_bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password: str) -> bool:
        return flask_bcrypt.check_password_hash(self.password_hash, password)

    def __repr__(self):
        return "<sysUser '{}'>".format(self.username)

    @staticmethod
    def init_table():
        rets = [
            ('张三', 'zhangsan@qq.com' , 'caefefq34q3e', 'sysadmin', None, None, '3423423', '这是第一个用户', False, None, False, None, None, None, None),
            ('李四', 'lisi@qq.com' ,'dqerq3q23e', 'representative', None, 1, '52253', '这是第二个用户', False, None, False, None, None, None, None),
            ('王五', 'wangwu@qq.com' , 'dedq3rq3daedq', 'representative', None, 1, '241441', '这是第二个用户', False, None, False, None, None, None, None),
        ]
        for ret in rets:
            user_obj = sysUser()
            user_obj.username = ret[0]
            user_obj.email = ret[1]
            user_obj.password_hash = ret[2]
            user_obj.sysrole = ret[3]
            user_obj.createtime = ret[4]
            user_obj.createdbyuid = ret[5]
            user_obj.mobile = ret[6]
            user_obj.comments = ret[7]
            user_obj.islocked = ret[8]
            user_obj.lockedbyuid = ret[9]
            user_obj.isfreezed = ret[10]
            user_obj.freezedbyuid = ret[11]
            user_obj.freezetime = ret[12]
            user_obj.modifiedbyuid = ret[13]
            user_obj.modifiedtime = ret[14]
            db.session.add(user_obj)
        db.session.commit()

# 被测对象
class targetUser(db.Model):
     """ User Model for storing user related details """
     __tablename__ = 't_tagUser'
     __table_args__ = {'comment': '被测对象表'}
     id = db.Column(db.INTEGER, primary_key=True, comment='用户编号')
     # 用户名指被测对象的真实姓名？
     username = db.Column(db.String(16), nullable=False, comment='用户名')
     createtime = db.Column(db.DateTime, default=datetime.now(), nullable=False, comment='创建时间')
     createdbyuid = db.Column(db.INTEGER, db.ForeignKey('t_sysUser.id', name='fk_created_by_uid', ondelete='NO ACTION'), nullable=False,
                              comment='创建人的编号,即对接人编号')
     create_sysuser = db.relationship("sysUser", backref=db.backref('create_tagusers', lazy='dynamic'),
                                       foreign_keys=[createdbyuid])
     email = db.Column(db.String(255), unique=True, nullable=False, comment='用户邮箱')
     orgid = db.Column(db.INTEGER, db.ForeignKey('t_organization.id', name='fk_organization_by_orgid', ondelete='CASCADE'), nullable=False, comment='所属部门编号')
     org = db.relationship("Organization", backref=db.backref('tagusers', lazy='dynamic'), foreign_keys=[orgid], primaryjoin='Organization.id == targetUser.orgid')
     position = db.Column(db.String(255), nullable=False, comment='职位')
     mobile = db.Column(db.String(11), comment='用户手机号')
     telephone = db.Column(db.String(8), comment='用户座机号')
     wechat_num = db.Column(db.String(28), comment='用户微信号')
     telecom_num = db.Column(db.String(20), comment='用户电报号')
     comments = db.Column(db.Text(5120), comment='备注')
     islocked = db.Column(db.BOOLEAN, default=False, comment='是否锁定')
     lockedbyuid = db.Column(db.INTEGER, db.ForeignKey('t_sysUser.id', name='fk_locked_by_uid', ondelete='SET NULL'), comment='锁定者编号')
     locke_sysuser = db.relationship("sysUser", backref=db.backref('lock_tagusers', lazy='dynamic'), foreign_keys=[lockedbyuid])
     lockedtime = db.Column(db.DateTime, comment='锁定时间')
     isfreezed = db.Column(db.BOOLEAN, default=False, comment='是否被冻结')
     freezedbyuid = db.Column(db.INTEGER, db.ForeignKey('t_sysUser.id', name='fk_freezed_by_uid', ondelete='SET NULL'), comment='冻结者编号')
     freeze_sysuser = db.relationship("sysUser", backref=db.backref('freeze_tagusers', lazy='dynamic'), foreign_keys=[freezedbyuid])
     freezetime = db.Column(db.DateTime, comment='冻结时间')
     modifiedbyuid = db.Column(db.INTEGER, db.ForeignKey('t_sysUser.id', name='fk_modified_by_uid', ondelete='SET NULL'), comment='修改者编号')
     modify_sysuser = db.relationship("sysUser", backref=db.backref('modify_tagusers', lazy='dynamic'), foreign_keys=[modifiedbyuid])
     modifiedtime = db.Column(db.DateTime, comment='修改时间')
     # 添加所属对接人ID
     representativeID = db.Column(db.INTEGER, db.ForeignKey('t_sysUser.id', name='fk_representative_uid', ondelete='CASCADE'), comment='所属对接人编号')
     representative_sysuser = db.relationship("sysUser", backref=db.backref('representative_tagusers', lazy='dynamic'),
                                      foreign_keys=[representativeID])

     def __repr__(self):
         return "<tagUser '{}'>".format(self.username)
     @staticmethod
     def init_table():
         rets = [
             ('将该', None, 3, 'jianghe@qq.com', 1, 'manager', '1431413','13134141', '14341efe', '41414', '这是3号客户代表的下属one',
              False, None, None,False, None, None, None, None, 2),
             ('放热峰', None, 3, 'fangrefeng@qq.com', 1, 'boss', '5245245', '55251414', '6564535', '1413424',
              '这是2号客户代表的下属two',
              False, None, None, False, None, None, None, None, 3),
         ]
         for ret in rets:
             user_obj = targetUser()
             user_obj.username = ret[0]
             user_obj.createtime = ret[1]
             user_obj.createdbyuid = ret[2]
             user_obj.email = ret[3]
             user_obj.orgid = ret[4]
             user_obj.position = ret[5]
             user_obj.mobile = ret[6]
             user_obj.telephone = ret[7]
             user_obj.wechat_num = ret[8]
             user_obj.telecom_num = ret[9]
             user_obj.comments = ret[10]
             user_obj.islocked = ret[11]
             user_obj.lockedbyuid = ret[12]
             user_obj.lockedtime = ret[13]
             user_obj.isfreezed = ret[14]
             user_obj.freezedbyuid = ret[15]
             user_obj.freezetime = ret[16]
             user_obj.modifiedbyuid = ret[17]
             user_obj.modifiedtime = ret[18]
             user_obj.representativeID = ret[19]
             db.session.add(user_obj)
         db.session.commit()