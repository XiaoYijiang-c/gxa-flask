from app.main import db
from datetime import datetime

class BlackList(db.Model):
    __tablename__ = 't_blacklist'
    __table_args__ = {'comment': '黑名单表'}
    id = db.Column(db.INTEGER, primary_key=True, comment='黑名单编号')
    jti = db.Column((db.String(36)), comment='JWT TOKEN ID')
    uid = db.Column(db.INTEGER,db.ForeignKey('t_sysUser.id', name='fk_releated_uid'), nullable=True, default=0, comment="用户ID")
    operatetime = db.Column(db.DateTime, default=datetime.now() , comment='创建时间')
    createdbyuid = db.Column(db.INTEGER, db.ForeignKey('t_sysUser.id', name='fk_created_by_uid'), comment='创建人的编号')
    comments = db.Column(db.Text(5120), comment='备注')
    def __repr__(self):
        return "<BlaskLiST '{}'>".format(self.id)
