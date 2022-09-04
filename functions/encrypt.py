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


class Encrypt(Resource):

    def get(self):
        return self._handle_encrypt()

    def post(self):
        return self._handle_encrypt()

    def _handle_encrypt(self):

        app.logger.info('Starting encrypt key')

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
            app.logger.error(f'Exception found for encrypt {e}')
            return jsonify({'function': 'encrypt',
                            'result': 404,
                            'description': 'wrong params.'})

        # symmetric encryption, only AES support for now
        try:
            key = key_reader.read_file(key_path)
            iv = key_reader.read_file(iv_path)
            msg = key_reader.read_file(file_to_enc)
            cipher = Cipher(algorithms.AES(key.encode()), modes.CBC(iv.encode()))
            encryptor = cipher.encryptor()
            ct = encryptor.update(msg.encode()) + encryptor.finalize()
            app.logger.info(f'Ciphertext is {ct}')

        except Exception as e:
            app.logger.error(f'Exception found for encrypt {e}')
            return jsonify({'function': 'encrypt',
                            'result': 500,
                            'description': 'Internal encryption errors'})

        try:
            with open(output, 'wb') as fp:
                fp.write(ct)
        except Exception as e:
            app.logger.error(f'Exception found for writing to file: {e}')
            return jsonify({'function': 'encrypt',
                            'result': 500,
                            'description': 'Cannot save ciphertext.'})

        app.logger.info(f'Flow finished. Operation successfully completed!')
        return jsonify({'function': 'encrypt',
                        'result': 200,
                        'description': 'Encryption finished!'})
