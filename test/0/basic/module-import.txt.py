# test `import muck`, as opposed to `from muck import *`.

import muck

print('module-import loaded:', muck.load('basic/a.txt'), end='')
