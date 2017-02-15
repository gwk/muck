print('''
from muck import *
from pithy.io import *

d_lines = list(clip_newlines(load('basic/d.txt')))
print('c:', d_lines)
''')
