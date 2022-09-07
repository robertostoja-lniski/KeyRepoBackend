from flask import jsonify, request, Flask
from flask_restful import Resource
from integration.syscall_lib_loader import get_repo_interface
from time import time
import ctypes
from jwt_utils.jwt_helper import get_jwt_token, get_from_jwt, NoProtectedDataError, get_key_from_jwt
from utils import key_reader
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
            interface = get_repo_interface()

            if key_id:
                uint64_key_id = ctypes.c_uint64(int(key_id))
            else:
                uint64_key_id = key_reader.read_prv_key_id(key_path)

            app.logger.info(f'Converted to key_id is {uint64_key_id}')

            start = time()
            result = interface.remove_key(uint64_key_id)
            end = time()

            elapsed_time = (end - start) * 1000

        except Exception as e:
            app.logger.error(f'[RemoveKey]: exception caught {e}')
            return jsonify({'function': 'remove_key'},
                           {'result': 'failed'},
                           {'qrepo_code': result})

        return jsonify({'function': 'remove_key',
                        'qrepo_code': result,
                        'result': 'success',
                        'elapsed_time': elapsed_time})
