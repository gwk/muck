from utest import *
from muck import *


for i in range(2):
  utest(f'a-to-many {i}\n', load(f'a-to-many-{i}.txt').read)
  utest(f'b-through {i}\n', load(f'b-through-{i}.txt').read)
