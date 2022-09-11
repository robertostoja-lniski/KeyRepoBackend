import json
from protected_access.helpers import io_handler
from integration.syscall_lib_loader import get_repo_interface
import subprocess
import os
import ctypes
import time
from getpass import getpass

def main():

    msg = io_handler.from_secret_file()
    result = None
    try:

        prv_key = msg['prv_key'].encode()
        prv_key_len = len(prv_key)

        prv_key_ptr =  ctypes.c_char_p(prv_key)

        password = msg['password']
        pass_ptr = ctypes.c_char_p(password.encode())
        password_len = len(password)

        uid = int(msg['uid'])
        gid = int(msg['gid'])

        key_id = ctypes.c_uint64(msg['key_id'])

        interface = get_repo_interface()        
        result = interface.read_key_uid(prv_key_ptr, key_id, pass_ptr, password_len, prv_key_len, uid, gid)

        msg['res_result'] = result
        msg['res_key'] = prv_key_ptr.value.decode()
        io_handler.to_secret_file(msg)

    except Exception as e:
        msg['exception'] = str(e)
        msg['res_result'] = None
        io_handler.to_secret_file(msg)
        return

    

if __name__ == '__main__':
    main()

