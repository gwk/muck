import os
from muck import *

_, name = argv

print('mod', name)
exit(int(os.environ['EXIT']))
