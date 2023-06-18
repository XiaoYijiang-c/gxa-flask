from app.main import db, flask_bcrypt
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
    # db.Column(db.INTEGER, comment='用户手机号')
    mobile = db.Column(db.INTEGER, comment='用户手机号')
    telephone = db.Column(db.String(8), comment='用户座机号')
    wechat_num = db.Column(db.String(28), comment='用户微信号')
    telecom_num = db.Column(db.String(20), comment='用户电报号')
    position = db.Column(db.String(255), comment='职位')
    comments = db.Column(db.Text(5120), comment='备注')
    createdbyuid = db.Column(db.INTEGER,  comment='创建人的编号')
    islocked = db.Column(db.BOOLEAN, comment='是否锁定')
    lockedbyuid = db.Column(db.INTEGER, comment='锁定者编号')
    lockedtime = db.Column(db.DateTime, comment='锁定时间')
    isfreezed = db.Column(db.BOOLEAN, comment='是否被冻结')
    freezedbyuid = db.Column(db.INTEGER, comment='冻结者编号')
    freezetime = db.Column(db.DateTime, comment='冻结时间')
    modifiedbyuid = db.Column(db.INTEGER, comment='修改者编号')
    modifiedtime = db.Column(db.DateTime, comment='修改时间')
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

    @staticmethod
    def init_table():
        rets = [
            ('张三', '$2b$12$H0YB6N1bWh9zBVbkvvRLMeIY0w.aJSuMSju.O70MWUfhLRRTIQea.', 'sysadmin', False, False, '这是第一个用户', None, None, None, None,'admin@qq.com'),
            # ('李四', 'dqerq3q23e', 'projectadmin', False, False, '这是第二个用户', 1, None, None, None,'lisi@qq.com'),
            # ('王五', 'dedq3rq3daedq', 'logadmin', False, False, '这是第二个用户', 2, None, None, 2,'wangwu@qq.com'),
        ]
        for ret in rets:
            user_obj = User()
            user_obj.username = ret[0]
            user_obj.password_hash = ret[1]
            user_obj.sysrole = ret[2]
            user_obj.islocked = ret[3]
            user_obj.isfreezed = ret[4]
            user_obj.comment = ret[5]
            user_obj.createdbyuid = ret[6]
            user_obj.modifiedbyuid = ret[7]
            user_obj.freezedbyuid = ret[8]
            user_obj.orgid = ret[9]
            user_obj.email = ret[10]
            db.session.add(user_obj)
        db.session.commit()