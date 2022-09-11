from flask import jsonify, request, Flask
from flask_restful import Resource
from integration.syscall_lib_loader import get_repo_interface
from time import time
from os import chmod
import os
from protected_access.helpers import io_handler
from subprocess import call

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

import ctypes
from jwt_utils.jwt_helper import get_from_jwt, get_key_from_jwt
from utils import key_reader
import logging

app = Flask(__name__)
app.logger.setLevel(logging.INFO)

class ReadKey(Resource):

    def get(self):
        return self._handle_read_key()

    def post(self):
        return self._handle_read_key()

    def _handle_read_key(self):

        app.logger.info('Starting handle read key')

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

            try:
                get_from_jwt(jwt_token, 'return_key_val')
                return_key_val = True
            except Exception as e:
                return_key_val = False

            if not return_key_val:
                export_key_path = get_from_jwt(jwt_token, 'export_key_path')
                app.logger.info(f'Received export key path: {export_key_path}')

            password = get_from_jwt(jwt_token, 'partition_pass')
            system_pass = get_from_jwt(jwt_token, 'system_pass')

        except Exception as e:
            app.logger.error(f'Exception found for read key {e}')
            return jsonify({'function': 'read_keys',
                            'result': 'failed',
                            'qrepo_code': None,
                            'description': 'wrong params.'})

        try:

            if key_id:
                key_id = int(key_id)
            else:
                key_id = key_reader.read_prv_key_id_int(key_path)
            app.logger.info(f'Converted to uint64 key_id is {key_id}')

            msg = {}
            msg['key_id'] = key_id
            msg['uid'] = os.getuid()
            msg['gid'] = os.getgid()
            io_handler.to_secret_file(msg)

            app.logger.info(f'Running sudo')
            cmd = "python3 -m protected_access.get_key_size"
            call('echo {} | sudo -S {}'.format(system_pass, cmd), shell=True)
            app.logger.info(f'Runned sudo')

            result_msg = io_handler.from_secret_file()
            app.logger.info(f'Got result from partition {result_msg}')

            if result_msg['res_result'] is None:
                raise Exception(result_msg['exception'])

            uint64_key_len = int(result_msg['res_key_size'])

        except Exception as e:
            app.logger.error(f'Exception for get key size: {e}')
            return jsonify({'function': 'read key',
                            'result': 'failed',
                            'qrepo_code': None,
                            'description': 'Cannot get key size'})

        try:
            pass_len = len(password)
            app.logger.info(f'Password key len is: {pass_len} to partition')

            msg = {}
            msg['prv_key'] = '_' * uint64_key_len
            msg['password'] = password
            msg['key_id'] = key_id
            msg['uid'] = os.getuid()
            msg['gid'] = os.getgid()
            io_handler.to_secret_file(msg)

            app.logger.info(f'Running sudo read')
            cmd = "python3 -m protected_access.read_key"
            call('echo {} | sudo -S {}'.format(system_pass, cmd), shell=True)
            app.logger.info(f'Runned sudo read')

            result_msg = io_handler.from_secret_file()
            app.logger.info(f'Got result from partition read {result_msg}')

            if result_msg['res_result'] is None:
                raise Exception(result_msg['exception'])

            prv_key = result_msg['res_key']

            with open(export_key_path, 'w') as fp:
                fp.write(prv_key)

        except FileExistsError as e:
            app.logger.error(f'File already exists: {e}')
            return jsonify({'function': 'read_key',
                            'result': 'failed',
                            'qrepo_code': result_msg['res_result'],
                            'description': 'File already exists'})

        except Exception as e:
            app.logger.error(f'Unhandled error: {e}')
            return jsonify({'function': 'read_key',
                            'result': 'failed',
                            'qrepo_code': None,
                            'description': 'Internal server error'})

        app.logger.info(f'Flow finished. Operation successfully completed!')
        return jsonify({'function': 'Get private key',
                        'result': 'success',
                        'qrepo_code': result_msg['res_result'],
                        'description': 'Key successfully read!'})
