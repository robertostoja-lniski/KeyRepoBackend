#!/usr/bin/python

import subprocess
import shlex
import sys
import getpass

def fun():
    print(f'Me: {getpass.getuser()}') 

print(f'This script was called by: {getpass.getuser()}') 

print('Now do something as root...')
subprocess.call(shlex.split('sudo', sys.executable, fun()))

print(f'Now switch back to the calling user: {getpass.getuser()}') 