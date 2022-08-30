from flask import jsonify, request
from flask_restful import Resource
from integration.syscall_lib_loader import get_repo_interface
from time import time
import ctypes
from jwt_utils.jwt_helper import get_from_jwt


class GetKeyNum(Resource):

    def get(self):
        return self._handle_get_key_num()

    def post(self):
        return self._handle_get_key_num()

    def _handle_get_key_num(self):

        jwt_token = request.args.get('protected_data')

        try:
            system_pass = get_from_jwt(jwt_token, 'my-secret', 'system_pass')

        except Exception:
            return jsonify({'function': 'get_key_num',
                           'result': 404, 'description': 'wrong params'})


        print(f'Reading data from repo')
        print(f'system pass {system_pass}')

        result = -1
        try:
            interface = get_repo_interface()
            key_num = ctypes.c_ulonglong()

            start = time()
            result = interface.get_key_num(ctypes.byref(key_num))
            end = time()

            elapsed_time = (end - start) * 1000

        except Exception as e:
            print(f'[GetKeyNum]: exception caught {e}')
            return jsonify({'function': 'get_key_num'},
                           {'result': result})

        return jsonify({'function': 'get_key_num',
                        'key_num': key_num.value,
                        'result': result,
                        'elapsed_time': elapsed_time})
