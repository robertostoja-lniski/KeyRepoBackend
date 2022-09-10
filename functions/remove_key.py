from flask import jsonify, request, Flask
from flask_restful import Resource
from subprocess import call
from integration.syscall_lib_loader import get_repo_interface
from protected_access.helpers import io_handler
from time import time
import json
import ctypes
import os
from jwt_utils.jwt_helper import get_jwt_token, get_from_jwt, NoProtectedDataError, get_key_from_jwt
from utils import key_reader
from protected_access.helpers.io_handler import to_secret_file
import logging
import subprocess

app = Flask(__name__)
app.logger.setLevel(logging.INFO)

class RemoveKey(Resource):

    def get(self):
        return self._handle_remove_key()

    def post(self):
        return self._handle_remove_key()

    def _handle_remove_key(self):

        app.logger.info('Starting handle remove key')

        try:
            jwt_token = get_jwt_token(request)
            app.logger.info(f'Get token {jwt_token}')
            
            # Support for frontend requirement.
            # Not recommended for CLI usage
            key_id = get_key_from_jwt(jwt_token)
            if key_id:
                app.logger.info(f'Received key_id: {key_id}')
            else:
                key_path = get_from_jwt(jwt_token, 'key_path')
                app.logger.info(f'Received key_path: {key_path}')
            
            system_pass = get_from_jwt(jwt_token, 'system_pass')

        except Exception as e:
            app.logger.error(f'Exception found for remove key: {e}')
            return jsonify({'function': 'get_key_mode',
                            'result': 'failed', 
                            'qrepo_code': None,
                            'description': 'wrong params'})

        result = None
        try:

            if key_id:
                int_key_id = int(key_id)
            else:
                int_key_id = key_reader.read_prv_key_id_int(key_path)

            app.logger.info(f'Converted to key_id is {int_key_id}')

            msg = {}
            msg['key_id'] = int_key_id
            msg['uid'] = os.getuid()
            msg['gid'] = os.getgid()
            io_handler.to_secret_file(msg)

            app.logger.info(f'Running sudo')
            cmd = "python3 -m protected_access.remove_key"
            call('echo {} | sudo -S {}'.format(system_pass, cmd), shell=True)
            app.logger.info(f'Runned sudo')

            result_msg = io_handler.from_secret_file()
            app.logger.info(f'Got result from partition {result_msg}')

            if result_msg['res_result'] is None:
                raise Exception(result_msg['exception'])

        except Exception as e:
            app.logger.error(f'[RemoveKey]: exception caught {e}')
            return jsonify({'function': 'remove_key',
                            'result': 'failed',
                            'qrepo_code': None})

        return jsonify({'function': 'remove_key',
                        'qrepo_code': result_msg['res_result'],
                        'result': 'success'})
