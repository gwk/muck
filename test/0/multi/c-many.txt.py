import muck

for vars, file in muck.load_many('a-to-many-%.txt', (0, 2)):
  print(*vars, ':', [line.strip() for line in file])
