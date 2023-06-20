from app.main import db
from app.main.model.blacklist import BlackList
def save_changes(data: BlackList) -> None:
    print('保存数据',data)
    db.session.add(data)
    db.session.commit()