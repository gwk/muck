from os import environ
from sys import argv

_, name = argv

print('mod', name)
exit(int(environ['EXIT']))
