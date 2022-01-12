from flask import jsonify
from flask_restful import Resource
from integration.syscall_lib_loader import get_repo_interface
from time import time


class GetKeyNum(Resource):
    def get(self):
        try:
            interface = get_repo_interface()

            start = time()
            key_num = interface.get_key_num()
            end = time()

            elapsed_time = (end - start) * 1000

        except Exception as e:
            print(f'[GetKeyNum]: exception caught {e}')
            return jsonify({'function': 'get_key_num'},
                           {'result': -1})

        return jsonify({'function': 'get_key_num',
                        'result': 0,
                        'key_num': key_num,
                        'elapsed_time': elapsed_time})
