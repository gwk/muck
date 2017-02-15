#!/usr/bin/env python3

from utest import *
from muck import *

def test(load_many_stream):
  for file, args in load_many_stream:
    yield file.read(), args

exp = [('load-many_0.\n', {'i':0}), ('load-many_1.\n', {'i':1})]

utest_seq(exp, test, load_many('client/load-many_{i}.txt', i=[0, 1]))
utest_seq(exp, test, load_many('client/load-many_{i}.txt', i={0, 1}))
utest_seq(exp, test, load_many('client/load-many_{i}.txt', i=(0, 1)))
utest_seq(exp, test, load_many('client/load-many_{i}.txt', i=range(2)))
