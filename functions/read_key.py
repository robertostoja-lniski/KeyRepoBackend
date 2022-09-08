from flask import jsonify, request, Flask
from flask_restful import Resource
from integration.syscall_lib_loader import get_repo_interface
from time import time
from os import chmod

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
            system_password = get_from_jwt(jwt_token, 'system_pass')

        except Exception as e:
            app.logger.error(f'Exception found for read key {e}')
            return jsonify({'function': 'read_keys',
                            'result': 'failed',
                            'qrepo_code': None,
                            'description': 'wrong params.'})

        try:
            interface = get_repo_interface()

            if key_id:
                uint64_key_id = ctypes.c_uint64(int(key_id))
            else:
                uint64_key_id = key_reader.read_prv_key_id(key_path)
            app.logger.info(f'Converted to uint64 key_id is {uint64_key_id}')

            uint64_key_len = ctypes.c_uint64()

            result = interface.get_key_size(uint64_key_id, ctypes.byref(uint64_key_len))
            app.logger.info(f'Result of get key size: {result}')
            app.logger.info(f'Key size is: {uint64_key_len}')

        except Exception as e:
            app.logger.error(f'Exception for read key: {e}')
            return jsonify({'function': 'read key',
                            'result': 'failed',
                            'qrepo_code': None,
                            'description': 'Cannot get key size'})

        if result != 0:
            app.logger.error(f'Error in Qrepo: {result}')
            return jsonify({'function': 'read key',
                            'result': 'failed',
                            'qrepo_code': None,
                            'description': 'Cannot get key size'})

        try:
            pass_len = len(password)
            app.logger.info(f'Password key len is: {pass_len} to partition')
            pass_ptr = ctypes.c_char_p(password.encode())

            buf = '_' * uint64_key_len.value
            prv_key = ctypes.c_char_p(buf.encode())

            app.logger.info(f'prv_key {prv_key}, key_id {uint64_key_id}, pass_ptr {pass_ptr}, pass_len {pass_len}, uint64_key_len {uint64_key_len}')

            ret = interface.read_key(prv_key, uint64_key_id, pass_ptr, pass_len, uint64_key_len)
            if ret != 0:
                app.logger.error(f'Flow finished. Operation NOT successfully completed!')
                return jsonify({'function': 'read_key',
                                'result': 'failed',
                                'qrepo_code': ret,
                                'description': 'Error found'})

            if return_key_val:
                 return jsonify({'function': 'Get private key',
                        'result': 'success',
                        'key_val': str(prv_key.value),
                        'qrepo_code': ret,
                        'description': 'Key successfully read!'})

            with open(export_key_path, 'w') as fp:
                fp.write(str(prv_key.value))

        except FileExistsError as e:
            app.logger.error(f'File already exists: {e}')
            return jsonify({'function': 'read_key',
                            'result': 'failed',
                            'qrepo_code': None,
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
                        'qrepo_code': ret,
                        'description': 'Key successfully read!'})
