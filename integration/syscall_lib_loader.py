from ctypes import *


def get_repo_interface():
    key_repo_so = "/Users/robertostoja-lniski/CLionProjects/KeyRepo/libkey_repo_lib.dylib"
    return CDLL(key_repo_so)
