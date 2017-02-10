from utest import *

import muck


exp = [('a-to-many 0\n', {'i':0}), ('a-to-many 1\n', {'i':1})]

def test(load_many_stream):
  for file, args in load_many_stream:
    yield file.read(), args

utest_seq(exp, test, muck.load_many('a-to-many-{i}.txt', i=[0, 1]))
utest_seq(exp, test, muck.load_many('a-to-many-{i}.txt', i={0, 1}))
utest_seq(exp, test, muck.load_many('a-to-many-{i}.txt', i=(0, 1)))
utest_seq(exp, test, muck.load_many('a-to-many-{i}.txt', i=range(0, 2)))

utest_val('a-to-many 0\n', muck.load('a-to-many-0.txt').read())
