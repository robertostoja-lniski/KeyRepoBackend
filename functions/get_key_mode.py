from flask import jsonify, request, Flask
from flask_restful import Resource
from integration.syscall_lib_loader import get_repo_interface
from time import time
import ctypes
from jwt_utils.jwt_helper import get_from_jwt
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
            key_id = get_from_jwt(jwt_token, 'key_id')
            app.logger.info(f'Received key_id: {key_id}')
        except ValueError:
            return jsonify({'function': 'get_key_mode',
                            'result': 404, 'description': 'wrong params'})

        result = -1
        try:
            interface = get_repo_interface()
            modes = ctypes.c_int()
            uint64_key_id = ctypes.c_uint64(int(key_id))
            app.logger.info(f'Converted to uint64 key_id is {uint64_key_id}')

            start = time()
            result = interface.get_mode(uint64_key_id, ctypes.byref(modes))
            end = time()

            elapsed_time = (end - start) * 1000

        except Exception as e:
            app.logger.error(f'[GetKeyMode]: exception caught {e}')
            return jsonify({'function': 'get_mode'},
                           {'result': result})

        return jsonify({'function': 'get_mode',
                        'modes': modes.value,
                        'key_repo_res': result,
                        'result': 200,
                        'elapsed_time': elapsed_time})
