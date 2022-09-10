import json
import os
from protected_access.helpers import io_handler

def main():
    print(f'As a root!')
    print(f'My uid is {os.getuid()}')
    msg_ret = io_handler.from_secret_file()
    print(f'Msg ret is {msg_ret}')

    msg_ret['sudo_ret'] = 0

    print(f'Msg ret is modified {msg_ret}')
    io_handler.to_secret_file(msg_ret)

if __name__ == '__main__':
    main()

