from flask import Flask, request
from flask_restful import Resource, Api
from functions.hello import HelloWorld
from functions.get_key_num import GetKeyNum

app = Flask(__name__)
app.config['JSON_SORT_KEYS'] = False
api = Api(app)


def init():
    api.add_resource(HelloWorld, '/')
    api.add_resource(GetKeyNum, '/getKeyNum')


def backend_run():
    init()
    app.run(debug=True)
