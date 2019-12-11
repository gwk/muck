#!/usr/bin/env python3

from sys import argv, executable
from os import environ
from os.path import abspath as abs_path
from pprint import pprint
from pithy.task import runC

_, *args  = argv

print('run-open.py:', executable)

env = environ.copy()
env['DYLD_INSERT_LIBRARIES'] = abs_path('muck/_libmuck.cpython-37m-darwin.so')
env['MUCK_DEPS_DBG'] = 'TRUE'

code = runC(['python3', 'test/interpose/open.py', *args], env=env, lldb=True)

if code: exit(f'failed with exit code {code}')
