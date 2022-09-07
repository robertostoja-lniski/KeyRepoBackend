from flask import jsonify, request, Flask
from flask_restful import Resource
from integration.syscall_lib_loader import get_repo_interface
from time import time
import ctypes
from jwt_utils.jwt_helper import get_from_jwt, get_key_from_jwt
from utils import key_reader
import logging

app = Flask(__name__)
app.logger.setLevel(logging.INFO)


class GetKeyMode(Resource):

    def get(self):
        return self._handle_get_key_mode()

    def post(self):
        return self._handle_get_key_mode()

    def _handle_get_key_mode(self):

        app.logger.info('Starting handle get key mode')

        try:
            jwt_token = request.args.get('protected_data')

            # Support for frontend requirement.
            # Not recommended for CLI usage
            key_id = get_key_from_jwt(jwt_token)
            if key_id:
                app.logger.info(f'Received key_id: {key_id}')
            else:
                key_path = get_from_jwt(jwt_token, 'key_path')
                app.logger.info(f'Received key_path: {key_path}')

        except ValueError:
            return jsonify({'function': 'get_key_mode',
                            'result': 'failed',
                            'qrepo_code': None,
                            'description': 'wrong params'})

        result = None
        try:
            interface = get_repo_interface()
            modes = ctypes.c_int()

            if key_id:
                uint64_key_id = ctypes.c_uint64(int(key_id))
            else:
                uint64_key_id = key_reader.read_prv_key_id(key_path)

            app.logger.info(f'Converted to uint64 key_id is {uint64_key_id}')

            start = time()
            result = interface.get_mode(uint64_key_id, ctypes.byref(modes))
            end = time()

            elapsed_time = (end - start) * 1000

        except Exception as e:
            app.logger.error(f'[GetKeyMode]: exception caught {e}')
            return jsonify({'function': 'get_mode',
                           'qrepo_code': result,
                           'result': 'failed'})

        return jsonify({'function': 'get_mode',
                        'modes': modes.value,
                        'qrepo_code': result,
                        'result': 'success',
                        'elapsed_time': elapsed_time})
