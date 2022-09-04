from flask import jsonify, request, Flask
from flask_restful import Resource
from integration.syscall_lib_loader import get_repo_interface
from time import time
from os import chmod

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

import ctypes
from jwt_utils.jwt_helper import get_from_jwt
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
            key_path = get_from_jwt(jwt_token, 'key_path')
            app.logger.info(f'Received private key path: {key_path}')

            export_key_path = get_from_jwt(jwt_token, 'export_key_path')
            app.logger.info(f'Received export key path: {export_key_path}')

            password = get_from_jwt(jwt_token, 'pass')

        except Exception as e:
            app.logger.error(f'Exception found for create key {e}')
            return jsonify({'function': 'read_keys',
                            'result': 404,
                            'description': 'wrong params.'})


        # temporary step - get key size
        try:
            interface = get_repo_interface()
            uint64_key_id = key_reader.read_prv_key_id(key_path)
            app.logger.info(f'Converted to uint64 key_id is {uint64_key_id}')

            uint64_key_len = ctypes.c_uint64()

            result = interface.get_key_size(uint64_key_id, ctypes.byref(uint64_key_len))
            app.logger.info(f'Result of get key size: {result}')
            app.logger.info(f'Key size is: {uint64_key_len}')

        except Exception as e:
            app.logger.error(f'Exception for read key: {e}')
            return jsonify({'function': 'read key',
                            'result': 500,
                            'description': 'Cannot get key size'})

        if result != 0:
            app.logger.error(f'Error in Qrepo: {result}')
            return jsonify({'function': 'read key',
                            'result_get_key_size': -1,
                            'result': 500,
                            'description': 'Cannot get key size'})

        # int read_key(char * key, uint64_t id, const char * pass, uint64_t pass_len, uint64_t key_len);
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
                                'result': ret,
                                'description': 'Error found'})

            with open(export_key_path, 'w') as fp:
                fp.write(str(prv_key.value))

        except FileExistsError as e:
            app.logger.error(f'File already exists: {e}')
            return jsonify({'function': 'read_key',
                            'result': 404,
                            'description': 'File already exists'})

        except Exception as e:
            app.logger.error(f'Unhandled error: {e}')
            return jsonify({'function': 'read_key',
                            'result': 500,
                            'description': 'Internal server error'})

        app.logger.info(f'Flow finished. Operation successfully completed!')
        return jsonify({'function': 'Get private key',
                        'result': 200,
                        'description': 'Key successfully read!'})
