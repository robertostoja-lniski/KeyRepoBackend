from flask import Flask, request, make_response
from flask_restful import Resource, Api
from functions.hello import SendWelcomeMessage
from functions.get_key_num import GetKeyNum
from functions.get_key_mode import GetKeyMode
from functions.set_key_mode import SetKeyMode
from functions.remove_key import RemoveKey
from functions.create_key import CreateKey
from functions.read_key import ReadKey
from functions.encrypt import Encrypt
from functions.decrypt import Decrypt
from functions.sign import Sign
from functions.check_signature import CheckSignature
from flask_cors import CORS, cross_origin
import logging

app = Flask(__name__)
app.config['JSON_SORT_KEYS'] = False
app.logger.setLevel(logging.DEBUG)
cors = CORS(app, resources={r"/*": {"origins": "*"}})
api = Api(app)


def init():
    api.add_resource(SendWelcomeMessage, '/')
    api.add_resource(GetKeyNum, '/getKeyNum')
    api.add_resource(GetKeyMode, '/getKeyMode')
    api.add_resource(SetKeyMode, '/setKeyMode')
    api.add_resource(RemoveKey, '/removeKey')
    api.add_resource(CreateKey, '/createKeys')
    api.add_resource(ReadKey, '/readKey')
    api.add_resource(Encrypt, '/encrypt')
    api.add_resource(Decrypt, '/decrypt')
    api.add_resource(Sign, '/sign')
    api.add_resource(CheckSignature, '/checkSignature')


def backend_run():
    init()
    try:
        # app.run(debug=True, ssl_context='adhoc')
        app.run(debug=True)
    except Exception as e:
        app.logger.error(f'Critical error {e}')
