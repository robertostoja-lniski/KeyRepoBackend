from flask import jsonify, request, Flask
from flask_restful import Resource
from integration.syscall_lib_loader import get_repo_interface
from time import time
import ctypes
from jwt_utils.jwt_helper import get_jwt_token, get_from_jwt, NoProtectedDataError
from utils import key_reader
import logging

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
            key_path = get_from_jwt(jwt_token, 'key_path')
            app.logger.info(f'Received key_path: {key_path}')
        except Exception as e:
            app.logger.error(f'Exception found for remove key: {e}')
            return jsonify({'function': 'get_key_mode',
                            'result': 'failed', 
                            'description': 'wrong params'})

        try:
            interface = get_repo_interface()
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
                        'key_repo_res': result,
                        'result': 'success',
                        'elapsed_time': elapsed_time})
