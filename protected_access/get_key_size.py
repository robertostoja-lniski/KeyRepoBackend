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

        key_id =  ctypes.c_uint64(msg['key_id'])
        uid = ctypes.c_int(msg['uid'])
        gid = ctypes.c_int(msg['gid'])

        key_size = ctypes.c_uint64()

        interface = get_repo_interface()
        result = interface.get_key_size_uid(key_id, ctypes.byref(key_size), uid, gid)

    except Exception as e:
        msg['exception'] = str(e)
        msg['res_result'] = result
        io_handler.to_secret_file(msg)
        return

    msg['res_result'] = result
    msg['res_key_size'] = key_size.value
    io_handler.to_secret_file(msg)

if __name__ == '__main__':
    main()

