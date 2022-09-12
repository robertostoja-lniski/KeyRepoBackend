import json
import logging
from flask import Flask
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from utils.config_parser import config_data

app = Flask(__name__)
app.logger.setLevel(logging.INFO)

def to_secret_file(msg):

    msg_str = json.dumps(msg)

    key_byte = config_data('secret_call', 'key')
    app.logger.info(f'Key values is {key_byte}')

    iv_byte = config_data('secret_call', 'iv')
    app.logger.info(f'Iv byte is {iv_byte}')

    cipher = Cipher(algorithms.AES(key_byte.encode()), modes.CBC(iv_byte.encode()))

    encryptor = cipher.encryptor()

    # padder = padding.PKCS7(128).padder()
    # msg_bytes = padder.update(msg_str.encode())
    app.logger.info(f'Current len is {len(msg_str)}')

    # Not an optimal solution, but efficiency is not a big issue for REST_API io
    msg_str_len = len(msg_str)
    padding_len = 16 - msg_str_len % 16
    app.logger.info(f'Padding of len {padding_len} will be added')
    # space is used for convenient json dumping and loading
    padding_vals = ' ' * padding_len
    msg_str += padding_vals

    ct = encryptor.update(msg_str.encode()) + encryptor.finalize()
    app.logger.info(f'Updated')

    interface = config_data('secret_call', 'interface')
    with open(interface, 'wb') as fp:
        fp.flush()
        fp.write(ct)

    app.logger.info(f'Saved')


def from_secret_file():

    interface = config_data('secret_call', 'interface')
    with open(interface, 'rb') as fp:
        msg = fp.read() 

    key_byte = config_data('secret_call', 'key')
    iv_byte = config_data('secret_call', 'iv')
    app.logger.info(f'Iv byte is {iv_byte}')

    cipher = Cipher(algorithms.AES(key_byte.encode()), modes.CBC(iv_byte.encode()))
    decryptor = cipher.decryptor()
    plain = decryptor.update(msg).decode()

    json_msg = json.loads(plain)

    return json_msg



