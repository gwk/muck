print('''
import muck
from pithy.io import *

d_lines = list(clip_newlines(muck.load('basic/d.txt')))
print('c:', d_lines)
''')
