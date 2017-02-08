from utest import *

import muck


exp = [(0, 'a-to-many 0'), (1, 'a-to-many 1')]

def test(load_many_stream):
  for args, file in load_many_stream:
    yield args[0], file.read().rstrip('\n')

utest_seq(exp, test, muck.load_many('a-to-many-{}.txt', [0, 1]))
utest_seq(exp, test, muck.load_many('a-to-many-{}.txt', {0, 1}))
utest_seq(exp, test, muck.load_many('a-to-many-{}.txt', (0, 1)))
utest_seq(exp, test, muck.load_many('a-to-many-{}.txt', range(0, 2)))

utest_val('a-to-many 0\n', muck.load('a-to-many-0.txt').read())
