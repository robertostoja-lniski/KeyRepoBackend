from flask import jsonify, request, Flask
from flask_restful import Resource
from time import time
from os import chmod

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

import ctypes
from jwt_utils.jwt_helper import get_from_jwt
from utils import key_reader
import logging

app = Flask(__name__)
app.logger.setLevel(logging.INFO)


class Decrypt(Resource):

    def get(self):
        return self._handle_decrypt()

    def post(self):
        return self._handle_decrypt()

    def _handle_decrypt(self):

        app.logger.info('Starting decrypt key')

        try:
            jwt_token = request.args.get('protected_data')
            key_path = get_from_jwt(jwt_token, 'key_path')
            app.logger.info(f'Received key path: {key_path}')

            iv_path = get_from_jwt(jwt_token, 'iv_path')
            app.logger.info(f'Received iv path: {iv_path}')

            file_to_enc = get_from_jwt(jwt_token, 'plain_file')
            app.logger.info(f'Received file path: {file_to_enc}')

            output = get_from_jwt(jwt_token, 'encrypted_file')
            app.logger.info(f'Received file path: {output}')

        except Exception as e:
            app.logger.error(f'Exception found for decrypt {e}')
            return jsonify({'function': 'decrypt',
                            'result': 404,
                            'description': 'wrong params.'})

        # symmetric encryption, only AES support for now
        try:
            key = key_reader.read_file(key_path)
            iv = key_reader.read_file(iv_path)
            ct = key_reader.read_buf_file(output)
            cipher = Cipher(algorithms.AES(key.encode()), modes.CBC(iv.encode()))
            decryptor = cipher.decryptor()
            plain = decryptor.update(ct)
            app.logger.info(f'Plain text is {plain}')


        except Exception as e:
            app.logger.error(f'Exception found for encrypt {e}')
            return jsonify({'function': 'decrypt',
                            'result': 500,
                            'description': 'Internal encryption errors'})

        plain_str = plain.decode()
        app.logger.info(f'Plain text in str is: {plain_str}')

        try:
            with open(output, 'w') as fp:
                fp.write(plain_str)

        except Exception as e:
            app.logger.error(f'Exception found for writing to file: {e}')
            return jsonify({'function': 'decrypt',
                            'result': 500,
                            'description': 'Cannot save plain text.'})

        app.logger.info(f'Flow finished. Operation successfully completed!')
        return jsonify({'function': 'decrypt',
                        'result': 200,
                        'description': 'Encryption finished!'})
