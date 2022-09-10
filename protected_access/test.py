import json
from protected_access.helpers import io_handler
import subprocess
import os
from getpass import getpass

def main():
    msg = {
        'key_id': 100
    }
    print(f'msg is {msg}')

    io_handler.to_secret_file(msg)

    print(f'My uid is {os.getuid()}')

    ls = "sudo python3 -m protected_access.protected_remove_sudo".split()
    cmd = subprocess.run(
        ls, stdout=subprocess.PIPE, input="triki", encoding="ascii",
    )
    print(cmd.stdout)

    msg_final = io_handler.from_secret_file()

    print(f'Main process has: {msg_final}')


if __name__ == '__main__':
    main()

