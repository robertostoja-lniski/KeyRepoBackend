import ctypes


class CannotReadPrvKeyError(Exception):
    pass


def read_prv_key_id(path):
    with open(path) as f:
        key_id = f.readlines()

        if len(key_id) == 0:
            raise CannotReadPrvKeyError('Empty key file')

        if len(key_id) > 1:
            raise CannotReadPrvKeyError('To many lines in key file')

    return ctypes.c_uint64(int(key_id[0]))

