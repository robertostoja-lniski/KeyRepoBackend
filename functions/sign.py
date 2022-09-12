from flask import jsonify, request, Flask
from flask_restful import Resource
from integration.syscall_lib_loader import get_repo_interface
from protected_access.helpers import io_handler
from time import time
from os import chmod
import os
from subprocess import call

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

import ctypes
from jwt_utils.jwt_helper import get_from_jwt, get_key_from_jwt
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
            # Support for frontend requirement.
            # Not recommended for CLI usage
            key_id = get_key_from_jwt(jwt_token)
            if key_id:
                app.logger.info(f'Received key_id: {key_id}')
            else:
                key_path = get_from_jwt(jwt_token, 'key_path')
                app.logger.info(f'Received key_path: {key_path}')

            message = get_from_jwt(jwt_token, 'plain_file')
            app.logger.info(f'Received message file path: {message}')

            output = get_from_jwt(jwt_token, 'signature')
            app.logger.info(f'Received signature file path: {output}')

            password = get_from_jwt(jwt_token, 'partition_pass')
            system_pass = get_from_jwt(jwt_token, 'system_pass')

        except Exception as e:
            app.logger.error(f'Exception found for sign {e}')
            return jsonify({'function': 'sign',
                            'result': 'failed',
                            'qrepo_code': None,
                            'description': 'wrong params.'})

        # temporary step - get key size
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
            app.logger.error(f'Exception for read key: {e}')
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

            if result_msg['res_result'] is None:
                raise Exception(result_msg['exception'])

            str_prv_key = result_msg['res_key']

        except Exception as e:
            app.logger.error(f'Unhandled error: {e}')
            return jsonify({'function': 'sign',
                            'result': 'failed',
                            'qrepo_code': None,
                            'description': 'Internal server error'})

        try:
            # create key structure from buffer
            prv_key_wrapper = serialization.load_pem_private_key(
                str_prv_key.encode(),
                password=None
            )

        except Exception as e:
            app.logger.error(f'Error when loading cert: {e}')
            return jsonify({'function': 'sign',
                            'result': 'failed',
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
                            'result': 'failed',
                            'qrepo_code': None,
                            'description': 'Error while signing process'})

        app.logger.info(f'Flow finished. Operation successfully completed!')
        return jsonify({'function': 'sign',
                        'result': 'success',
                        'qrepo_code': 0,
                        'description': 'Encryption finished!'})
