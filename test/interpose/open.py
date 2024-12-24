#!/usr/bin/env python3

# NOTE: /usr/bin/env will strip the DYLD_ variables from the environment, resulting in test failure.

from os import environ
from sys import argv, executable


print('open.py executable:', executable)

if 'DYLD_INSERT_LIBRARIES' not in environ:
  exit('DYLD_INSERT_LIBRARIES is not in env.')

for path in argv[1:]:
  print("opening:", path)
  open(path)

print('open.py: done.')
