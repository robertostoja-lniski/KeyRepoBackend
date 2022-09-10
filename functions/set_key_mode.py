from flask import jsonify, request, Flask
from flask_restful import Resource
from integration.syscall_lib_loader import get_repo_interface
from time import time
from subprocess import call
import os
import ctypes
from jwt_utils.jwt_helper import get_from_jwt, get_key_from_jwt
from utils import key_reader
import logging
from protected_access.helpers import io_handler

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

            system_pass = get_from_jwt(jwt_token, 'system_pass')

        except Exception as e:
            app.logger.error(f'Exception found for set key mode: {e}')
            return jsonify({'function': 'set_mode',
                            'result': 'failed',
                            'qrepo_code': None,
                            'description': 'wrong params'})

        try:

            if key_id:
                int_key_id = int(key_id)
            else:
                int_key_id = key_reader.read_prv_key_id_int(key_path)

            app.logger.info(f'Converted to uint64 key_id is {int_key_id}')

            msg = {}
            msg['key_id'] = int_key_id

            app.logger.info(f'Converted to int modes are {int(modes)}')
            msg['modes'] = int(modes)

            msg['uid'] = os.getuid()
            msg['gid'] = os.getgid()
            io_handler.to_secret_file(msg)

            app.logger.info(f'Running sudo')
            cmd = "python3 -m protected_access.set_key_mode"
            call('echo {} | sudo -S {}'.format(system_pass, cmd), shell=True)
            app.logger.info(f'Runned sudo')

            result_msg = io_handler.from_secret_file()
            app.logger.info(f'Got result from partition {result_msg}')

            if result_msg['res_result'] is None:
                raise Exception(result_msg['exception'])

        except Exception as e:
            app.logger.error(f'[SetKeyMode]: exception caught {e}')
            return jsonify({'function': 'set_mode',
                            'qrepo_code': None,
                            'result': 'failed'})

        return jsonify({'function': 'set_mode',
                        'qrepo_code': result_msg['res_result'],
                        'result': 'success'})
