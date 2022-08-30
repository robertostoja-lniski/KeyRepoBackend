from ctypes import *
from utils.config_parser import config_data


def get_repo_interface():
    key_repo_so = "/Users/robertostoja-lniski/CLionProjects/KeyRepo/libkey_repo_lib.dylib"
    different_path = config_data('lib', 'lib_path')
    print(f'Path vs path: {key_repo_so} {different_path}')
    return CDLL(key_repo_so)
