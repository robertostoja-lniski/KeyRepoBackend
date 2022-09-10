from flask import jsonify, request, Flask
from flask_restful import Resource
from integration.syscall_lib_loader import get_repo_interface
from protected_access.helpers import io_handler
from time import time
import os
from subprocess import call
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

            system_pass = get_from_jwt(jwt_token, 'system_pass')

        except ValueError:
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

            app.logger.info(f'Converted to uint64 key_id is {int_key_id}')

            msg = {}
            msg['key_id'] = int_key_id
            msg['uid'] = os.getuid()
            msg['gid'] = os.getgid()
            io_handler.to_secret_file(msg)

            app.logger.info(f'Running sudo')
            cmd = "python3 -m protected_access.get_key_mode"
            call('echo {} | sudo -S {}'.format(system_pass, cmd), shell=True)
            app.logger.info(f'Runned sudo')

            result_msg = io_handler.from_secret_file()
            app.logger.info(f'Got result from partition {result_msg}')

            if result_msg['res_result'] is None:
                raise Exception(result_msg['exception'])

        except Exception as e:
            app.logger.error(f'[GetKeyMode]: exception caught {e}')
            return jsonify({'function': 'get_mode',
                           'qrepo_code': None,
                           'result': 'failed'})

        return jsonify({'function': 'get_mode',
                        'modes': result_msg['modes'],
                        'qrepo_code': result_msg['res_result'],
                        'result': 'success'})
