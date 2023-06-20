from app.main import db, flask_bcrypt
from datetime import datetime

class trickSituation(db.Model):
    __tablename__ = 't_tricksituation'
    __table_args__ = {'comment': '中招情况表'}
    id = db.Column(db.INTEGER, primary_key=True, comment='中招编号')
    tricktime = db.Column(db.DateTime, default=datetime.now(), comment='中招时间')
    taguid = db.Column(db.INTEGER, db.ForeignKey('t_tagUser.id', name='fk_releated_uid'), nullable=True, default=0, comment="被测用户ID")
    taskid = db.Column(db.INTEGER, db.ForeignKey('t_tagUser.id', name='fk_releated_taskid'), nullable=True, default=0, comment="测评任务ID")
    action = db.Column(db.String(255), comment='被测用户动作')
    inputContent = db.Column(db.Text(5120), comment='输入的敏感内容')
    comments = db.Column(db.Text(5120), comment='备注')
    def __repr__(self):
        return "<trickSituation '{}'>".format(self.id)
