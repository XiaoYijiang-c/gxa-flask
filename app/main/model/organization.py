from .. import db
from datetime import datetime
from sqlalchemy import Sequence


class Organization(db.Model):
    __tablename__ = 't_organization'
    __table_args__ = {'comment': '部门表'}
    id = db.Column(db.INTEGER, primary_key=True, autoincrement=True, comment='部门编号')
    name = db.Column(db.String(16), nullable=False, comment='部门名称')
    istoporg = db.Column(db.INT, nullable=False, comment='是否是顶级组织')
    higherorgid = db.Column(db.INTEGER, nullable=False, default=0, comment='上级部门编号;若已经为顶级单位，父级单位则为0')
    islocked = db.Column(db.BOOLEAN, nullable=False, comment='是否锁定')
    createdbyuid = db.Column(db.INTEGER, nullable=False, comment='创建人编号')
    createtime = db.Column(db.DateTime, nullable=False, default=datetime.now(), comment='创建时间')
    logopath = db.Column(db.String(255), comment='图标路径')
    comments = db.Column(db.String(5120), comment='备注')
    modifiedbyuid = db.Column(db.INTEGER, comment='发起修改的用户编号')
    modifytime = db.Column(db.DateTime, comment='修改时间')

    @staticmethod
    def init_table():
        rets = [
            ('PRIVATE',True,0,),("SCU"), ("DZKD")
        ]
        for ret in rets:
            organization_obj = Organization()
            organization_obj.name = ret[0]
            db.session.add(organization_obj)
        db.session.commit()
