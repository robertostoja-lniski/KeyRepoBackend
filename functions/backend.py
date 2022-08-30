from flask import Flask, request, make_response
from flask_restful import Resource, Api
from functions.hello import HelloWorld
from functions.get_key_num import GetKeyNum
from flask_cors import CORS, cross_origin
import logging

app = Flask(__name__)
app.config['JSON_SORT_KEYS'] = False
app.logger.setLevel(logging.DEBUG)
cors = CORS(app, resources={r"/getKeyNum/*": {"origins": "*"}})
api = Api(app)


@app.route('/login')
def login():
    auth = request.authorization
    if auth and auth.password == "password":
        return ''

    return make_response('Could verify!', 401, {'WWW-Authenticate': 'Basic realm="Login Required"'})


def init():
    api.add_resource(HelloWorld, '/')
    api.add_resource(GetKeyNum, '/getKeyNum')


def backend_run():
    init()
    # app.run(debug=True, ssl_context='adhoc')
    app.run(debug=True)
