from flask import jsonify, request, Flask
from flask_restful import Resource
from integration.syscall_lib_loader import get_repo_interface
from time import time
from os import chmod

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

import ctypes
from jwt_utils.jwt_helper import get_from_jwt
from utils import key_reader
import logging

app = Flask(__name__)
app.logger.setLevel(logging.INFO)


class Sign(Resource):

    def get(self):
        return self._handle_sign()

    def post(self):
        return self._handle_sign()

    def _handle_sign(self):

        app.logger.info('Starting sign')

        try:
            jwt_token = request.args.get('protected_data')
            key_path = get_from_jwt(jwt_token, 'key_path')
            app.logger.info(f'Received key path: {key_path}')

            message = get_from_jwt(jwt_token, 'plain_file')
            app.logger.info(f'Received message file path: {message}')

            output = get_from_jwt(jwt_token, 'signature')
            app.logger.info(f'Received signature file path: {output}')

            password = get_from_jwt(jwt_token, 'pass')

        except Exception as e:
            app.logger.error(f'Exception found for sign {e}')
            return jsonify({'function': 'sign',
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
            return jsonify({'function': 'sign',
                            'result_sign': -1,
                            'result': 500,
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
                return jsonify({'function': 'sign',
                                'result': ret,
                                'description': 'Error found'})

        except Exception as e:
            app.logger.error(f'Unhandled error: {e}')
            return jsonify({'function': 'sign',
                            'result': 500,
                            'description': 'Internal server error'})

        str_prv_key = str(prv_key.value)
        app.logger.info(f'Key value: {str(prv_key.value)}')

        try:
            # create key structure from buffer
            prv_key_wrapper = serialization.load_pem_private_key(
                prv_key.value,
                password=None
            )
        except Exception as e:
            app.logger.error(f'Error when loading cert: {e}')
            return jsonify({'function': 'sign',
                            'result': 500,
                            'description': 'Cannot load pem prv key'})


        try:
            message_val = key_reader.read_buf_file(message)
            signature = prv_key_wrapper.sign(
                message_val,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )

            app.logger.info(f'File is signed {signature}')
            with open(output, 'wb') as fp:
                fp.write(signature)


        except Exception as e:
            app.logger.error(f'Unhandled error: {e}')
            return jsonify({'function': 'sign',
                            'result': 500,
                            'description': 'Error while signing process'})

        app.logger.info(f'Flow finished. Operation successfully completed!')
        return jsonify({'function': 'sign',
                        'result': 200,
                        'description': 'Encryption finished!'})
