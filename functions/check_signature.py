from cryptography.exceptions import InvalidSignature
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


class CheckSignature(Resource):

    def get(self):
        return self._handle_check_signature()

    def post(self):
        return self._handle_check_signature()

    def _handle_check_signature(self):

        app.logger.info('Starting check signature')

        try:
            jwt_token = request.args.get('protected_data')
            pub_key_path = get_from_jwt(jwt_token, 'pub_key_path')
            app.logger.info(f'Received pub key path: {pub_key_path}')

            message = get_from_jwt(jwt_token, 'plain_file')
            app.logger.info(f'Received message file path: {message}')

            input_signature = get_from_jwt(jwt_token, 'signature')
            app.logger.info(f'Received signature file path: {input_signature}')

        except Exception as e:
            app.logger.error(f'Exception found for sign {e}')
            return jsonify({'function': 'sign',
                            'result': 'failed',
                            'qrepo_code': None,
                            'description': 'wrong params.'})

        try:
            # create key structure from buffer
            with open(pub_key_path, "r") as fp:
                pub_key = serialization.load_pem_public_key(
                    fp.read().encode()
                )

            app.logger.info(f'Public key structure: {str(pub_key)}')

        except Exception as e:
            app.logger.error(f'Error when loading cert: {e}')
            return jsonify({'function': 'check_signature',
                            'result': 'failed',
                            'qrepo_code': None,
                            'description': 'Cannot load pub key'})

        result = 'OK'
        try:
            message_val = key_reader.read_buf_file(message)
            app.logger.info(f'Checking message {message_val}')

            signature_val = key_reader.read_buf_file(input_signature)
            app.logger.info(f'Checking signature {signature_val}')

            pub_key.verify(
                signature_val,
                message_val,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )

            app.logger.info(f'Signature ok!')

        except InvalidSignature:
            app.logger.info(f'Signature not ok!')
            result = 'NOT OK'

        except Exception as e:
            app.logger.error(f'Unhandled error: {e}')
            return jsonify({'function': 'check_signature',
                            'result': 'failed',
                            'qrepo_code': None,
                            'description': 'Error while check signature process'})

        app.logger.info(f'Flow finished. Operation successfully completed!')
        return jsonify({'function': 'check_signature',
                        'result': 'success',
                        'qrepo_code': result,
                        'description': 'Encryption finished!'})
