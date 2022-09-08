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
            app.logger.info(f'Received modes: {modes}')

            # Support for frontend requirement.
            # Not recommended for CLI usage
            key_id = get_key_from_jwt(jwt_token)
            if key_id:
                app.logger.info(f'Received key_id: {key_id}')
            else:
                key_path = get_from_jwt(jwt_token, 'key_path')
                app.logger.info(f'Received key_path: {key_path}')

        except Exception as e:
            app.logger.error(f'Exception found for set key mode: {e}')
            return jsonify({'function': 'set_mode',
                            'result': 'failed',
                            'qrepo_code': None,
                            'description': 'wrong params'})

        try:
            interface = get_repo_interface()
            int_modes = ctypes.c_int(int(modes))

            if key_id:
                uint64_key_id = ctypes.c_uint64(int(key_id))
            else:
                uint64_key_id = key_reader.read_prv_key_id(key_path)

            app.logger.info(f'Converted to int modes are {int_modes}')
            app.logger.info(f'Converted to key_id is {uint64_key_id}')

            start = time()
            result = interface.set_mode(uint64_key_id, int_modes)
            end = time()

            elapsed_time = (end - start) * 1000

        except Exception as e:
            app.logger.error(f'[SetKeyMode]: exception caught {e}')
            return jsonify({'function': 'set_mode',
                            'qrepo_code': None,
                            'result': 'failed'})

        return jsonify({'function': 'set_mode',
                        'qrepo_code': result,
                        'result': 'success',
                        'elapsed_time': elapsed_time})
