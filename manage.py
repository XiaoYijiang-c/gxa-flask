import os
import unittest
from flask_migrate import Migrate
from app import api_blueprint
from app.main import create_app, db
from app.main.model import organization, user
from flask import Response

app = create_app(os.getenv('BOILERPLATE_ENV') or 'dev')
app.register_blueprint(api_blueprint)

app.app_context().push()
migrate = Migrate(app, db)

# 初始化数据库
from app.main.model.user import User
from app.main.model.newuser import sysUser,targetUser
@app.route('/init_db')
def initDB():
    db.drop_all()
    db.create_all()
    # 初始化记录
    User.init_table()
    sysUser.init_table()
    targetUser.init_table()
    return "db initialed"

# @app.after_request
# def apply_caching(response):
#     response.headers["Access-Control-Allow-Credentials"] = "true"
#     response.headers["Access-Control-Allow-Origin"] = "*"
#     return response

@app.cli.command("run")
def run():
    print('这里')
    app.run(host="0.0.0.0", debug=True)



@app.cli.command("test")
def test():
    """Runs the unit tests."""
    print('测试')
    tests = unittest.TestLoader().discover('app/test', pattern='test*.py')
    result = unittest.TextTestRunner(verbosity=2).run(tests)
    if result.wasSuccessful():
        return 0
    return 1



if __name__ == '__main__':
    app.run(host="0.0.0.0", debug=True)
