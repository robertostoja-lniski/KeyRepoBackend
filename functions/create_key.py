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

class AlgorithmNotSupportedError(Exception):
    pass

class NonNumericKenLen(Exception):
    pass

class CreateKey(Resource):

    def get(self):
        return self._handle_create_key()

    def post(self):
        return self._handle_create_key()

    def _handle_create_key(self):

        app.logger.info('Starting handle remove key')

        try:
            jwt_token = request.args.get('protected_data')
            key_path = get_from_jwt(jwt_token, 'key_path')
            app.logger.info(f'Received private key path: {key_path}')

            pub_key_path = get_from_jwt(jwt_token, 'pub_key_path')
            app.logger.info(f'Received public key path: {pub_key_path}')

            password = get_from_jwt(jwt_token, 'pass')

            algo = request.args.get('algo')
            app.logger.info(f'Received algo: {algo}')
            if algo != 'RSA':
                raise AlgorithmNotSupportedError('Only RSA supported!')

            key_len_str = request.args.get('key_len')
            if not key_len_str:
                raise NonNumericKenLen('No value for key len.')

            key_len = int(key_len_str)
            app.logger.info(f'Received key len: {key_len}')

        except AlgorithmNotSupportedError as e:
            app.logger.error(f'Exception caught {e}')
            return jsonify({'function': 'create_keys',
                            'result': 404, 'description': 'Use algo=RSA'})

        except NonNumericKenLen as e:
            app.logger.error(f'Exception caught {e}')
            return jsonify({'function': 'create_keys',
                            'result': 404, 'description': 'No param key_len'})

        except Exception as e:
            app.logger.error(f'Exception found for create key {e}')
            return jsonify({'function': 'create_keys',
                            'result': 404,
                            'description': 'wrong params.'})

        prv_key_gen = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_len
        )

        # password support in next version of Qrepo
        prv_key = prv_key_gen.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        pub_key = pem_public_key = prv_key_gen.public_key().public_bytes(
          encoding=serialization.Encoding.PEM,
          format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        try:

            interface = get_repo_interface()
            private_key_len = len(prv_key)
            app.logger.info(f'Writing key of len: {private_key_len} to partition')

            pass_len = len(password)
            app.logger.info(f'Password key len is: {pass_len} to partition')

            # prv_key is already a byte array - no need to convert
            prv_key_ptr = ctypes.c_char_p(prv_key)
            pass_ptr = ctypes.c_char_p(password.encode())

            key_id = ctypes.c_uint64()
            key_id_ref = ctypes.byref(key_id)

            ret = interface.write_key(prv_key_ptr, private_key_len, pass_ptr, pass_len, key_id_ref, 1)
            app.logger.info(f'Create key ret is: {ret}')

            with open(key_path, 'w') as fp:
                fp.write(prv_key.decode())

            with open(pub_key_path, 'w') as fp:
                fp.write(pub_key.decode())

        except FileExistsError as e:
            app.logger.error(f'File already exists: {e}')
            return jsonify({'function': 'create_keys',
                            'result': 404,
                            'description': 'File already exists'})

        app.logger.info(f'Flow finished. Operation successfully completed!')
        return jsonify({'function': 'create_keys',
                        'result': 200,
                        'description': 'Keys created, prv key written to partition!'})
