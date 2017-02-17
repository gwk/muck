# test `import muck`, as opposed to `from muck import *`.

import muck

print('module-import loaded:', muck.load('a.txt').read(), end='')
