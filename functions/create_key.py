from flask import jsonify, request, Flask
from flask_restful import Resource
from integration.syscall_lib_loader import get_repo_interface
from protected_access.helpers import io_handler
from time import time
from subprocess import call
from os import chmod
import os

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

            password = get_from_jwt(jwt_token, 'partition_pass')
            system_pass = get_from_jwt(jwt_token, 'system_pass')

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
                            'qrepo_code': None,
                            'result': 'failed',
                            'description': 'Use algo=RSA'})

        except NonNumericKenLen as e:
            app.logger.error(f'Exception caught {e}')
            return jsonify({'function': 'create_keys',
                            'qrepo_code': None,
                            'result': 'failed',
                            'description': 'No param key_len'})

        except Exception as e:
            app.logger.error(f'Exception found for create key {e}')
            return jsonify({'function': 'create_keys',
                            'result': 'failed',
                            'qrepo_code': None,
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

        pub_key = prv_key_gen.public_key().public_bytes(
          encoding=serialization.Encoding.PEM,
          format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        try:

            app.logger.info(f'Writing key of len: {len(prv_key)} to partition')
            app.logger.info(f'Password key len is: {len(password)} to partition')

            msg = {}
            msg['prv_key'] = prv_key.decode()
            msg['password'] = password
            msg['uid'] = os.getuid()
            msg['gid'] = os.getgid()
            io_handler.to_secret_file(msg)

            app.logger.info(f'Running sudo')
            cmd = "python3 -m protected_access.create_key"
            call('echo {} | sudo -S {}'.format(system_pass, cmd), shell=True)
            app.logger.info(f'Runned sudo')

            result_msg = io_handler.from_secret_file()
            app.logger.info(f'Got result from partition {result_msg}')

            if result_msg['res_result'] is None:
                raise Exception(result_msg['exception'])

            with open(pub_key_path, 'w') as fp:
                fp.write(pub_key.decode())

            with open(key_path, 'w') as fp:
                fp.write(result_msg['res_key_id'])

        except FileExistsError as e:
            app.logger.error(f'File already exists: {e}')
            return jsonify({'function': 'create_keys',
                            'result': 'failed',
                            'qrepo_code': None,
                            'description': 'File already exists'})

        if result_msg['res_result'] != 0:
            app.logger.error(f'Flow finished. Operation NOT successfully completed!')
            return jsonify({'function': 'create_keys',
                            'result': 'failed',
                            'qrepo_code': result_msg['res_result'],
                            'description': 'Error found'})

        app.logger.info(f'Flow finished. Operation successfully completed!')
        return jsonify({'function': 'create_keys',
                        'result': 'success',
                        'qrepo_code': 0,
                        'description': 'Keys created, prv key written to partition!'})
