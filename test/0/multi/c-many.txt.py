from utest import *

for i in range(2):
  utest(f'a-to-many {i}\n', open(f'a-to-many-{i}.txt').read)
  utest(f'b-through {i}\n', open(f'b-through-{i}.txt').read)
