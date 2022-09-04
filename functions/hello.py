from flask import jsonify, request, Flask
from flask_restful import Resource
from integration.syscall_lib_loader import get_repo_interface
from time import time
import ctypes
from jwt_utils.jwt_helper import get_from_jwt
import logging

app = Flask(__name__)
app.logger.setLevel(logging.INFO)


class SendWelcomeMessage(Resource):

    def get(self):
        return self._handle_send_welcome_message()

    def post(self):
        return self._handle_send_welcome_message()

    def _handle_send_welcome_message(self):

        app.logger.info('Starting handle get key num')
        return jsonify({'function': 'send_welcome_message',
                        'description': 'Welcome to Qrepo!'})
