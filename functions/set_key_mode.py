from flask import jsonify, request, Flask
from flask_restful import Resource
from integration.syscall_lib_loader import get_repo_interface
from time import time
import ctypes
from jwt_utils.jwt_helper import get_from_jwt
import logging

app = Flask(__name__)
app.logger.setLevel(logging.INFO)


class SetKeyMode(Resource):

    def get(self):
        return self._handle_set_key_mode()

    def post(self):
        return self._handle_set_key_mode()

    def _handle_set_key_mode(self):

        app.logger.info('Starting handle set key mode')

        try:
            jwt_token = request.args.get('protected_data')
            modes = get_from_jwt(jwt_token, 'modes')
            key_id = get_from_jwt(jwt_token, 'key_id')
            app.logger.info(f'Received modes: {modes}')
            app.logger.info(f'Received key_id: {key_id}')
        except Exception:
            app.logger.error('Exception found for set key mode')
            return jsonify({'function': 'get_key_mode',
                            'result': 404, 'description': 'wrong params'})

        try:
            interface = get_repo_interface()
            int_modes = ctypes.c_int(int(modes))
            uint64_key_id = ctypes.c_uint64(int(key_id))

            app.logger.info(f'Converted to int modes are {int_modes}')
            app.logger.info(f'Converted to key_id is {uint64_key_id}')

            start = time()
            result = interface.set_mode(uint64_key_id, int_modes)
            end = time()

            elapsed_time = (end - start) * 1000

        except Exception as e:
            app.logger.error(f'[SetKeyMode]: exception caught {e}')
            return jsonify({'function': 'set_mode'},
                           {'result': result})

        return jsonify({'function': 'set_mode',
                        'key_repo_res': result,
                        'result': 200,
                        'elapsed_time': elapsed_time})
