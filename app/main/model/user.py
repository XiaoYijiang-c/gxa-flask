from .. import db, flask_bcrypt
from datetime import datetime

class User(db.Model):
    """ User Model for storing user related details """
    __tablename__ = 't_user'
    __table_args__ = {'comment': '用户表'}

    id = db.Column(db.INTEGER, primary_key=True, comment='用户编号')
    username = db.Column(db.String(16), nullable=False, comment='用户名')
    orgid = db.Column(db.INTEGER, comment='所属部门编号')
    sysrole = db.Column(db.String(255), nullable=False, comment='系统角色：sysadmin | logadmin | projectadmin | projectowner')
    createtime = db.Column(db.DateTime, default=datetime.now(), nullable=False, comment='创建时间')
    password_hash = db.Column(db.String(100), comment='密码hash')
    email = db.Column(db.String(255), unique=True, nullable=False, comment='用户邮箱')
    mobile = db.Column(db.INTEGER, comment='用户手机号')
    telephone = db.Column(db.String(20), comment='用户座机号')
    wechat_num = db.Column(db.String(20), comment='用户微信号')
    telecom_num = db.Column(db.String(20), comment='用户电报号')
    position = db.Column(db.String(255), comment='职位')
    comments = db.Column(db.String(5120), comment='备注')
    createdbyuid = db.Column(db.INTEGER, comment='创建人的编号')
    islocked = db.Column(db.BOOLEAN, comment='是否锁定')
    isfreezed = db.Column(db.BOOLEAN, comment='是否被冻结')
    freezedbyuid = db.Column(db.INTEGER, comment='冻结者编号')
    freezetime = db.Column(db.DateTime, comment='冻结时间')

    @property
    def password(self):
        raise AttributeError('password: write-only field')

    @password.setter
    def password(self, password):
        self.password_hash = flask_bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password: str) -> bool:
        return flask_bcrypt.check_password_hash(self.password_hash, password)

    def __repr__(self):
        return "<User '{}'>".format(self.username)