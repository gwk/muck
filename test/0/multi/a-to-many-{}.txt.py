import muck

for i in range(2):
  print('a-to-many', i, file=muck.dst_file(i))
