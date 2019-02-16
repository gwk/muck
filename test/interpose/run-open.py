#!/usr/bin/env python3.7

from sys import argv, executable
from os import environ
from os.path import abspath as abs_path
from pprint import pprint
#from subprocess import run
from pithy.task import runC

_, libmuck, *args  = argv

print('run-open.py:', executable)

env = environ.copy()
env['DYLD_INSERT_LIBRARIES'] = abs_path(libmuck)
env['MUCK_DEPS_DBG'] = 'TRUE'

lldb = '/Applications/Xcode.app/Contents/Developer/usr/bin/lldb'
python = '/Library/Frameworks/Python.framework/Versions/3.7/bin/python3'
code = runC([lldb, 'python3', 'test/interpose/open.py', *args], env=env)
if code: exit(f'failed with exit code {code}')
