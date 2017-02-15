from utest import *
from muck import *


def test(load_many_stream):
  for file, args in load_many_stream:
    yield file.read(), args

a_exp = [('a-to-many 0\n', {'i':0}), ('a-to-many 1\n', {'i':1})]
b_exp = [('b-through 0\n', {'i':0}), ('b-through 1\n', {'i':1})]

utest_seq(a_exp, test, load_many('a-to-many-{i}.txt', i=range(2)))
utest_seq(b_exp, test, load_many('b-through-{i}.txt', i=range(2)))

utest_val('a-to-many 0\n', load('a-to-many-0.txt').read())
utest_val('b-through 0\n', load('b-through-0.txt').read())
