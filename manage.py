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

@app.after_request
def apply_caching(response):
    response.headers["Access-Control-Allow-Credentials"] = "true"
    return response

@app.cli.command("run")
def run():
    app.run(host="0.0.0.0", debug=True)



@app.cli.command("test")
def test():
    """Runs the unit tests."""
    tests = unittest.TestLoader().discover('app/test', pattern='test*.py')
    result = unittest.TextTestRunner(verbosity=2).run(tests)
    if result.wasSuccessful():
        return 0
    return 1



if __name__ == '__main__':
    app.run()
