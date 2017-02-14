import muck

f = muck.load('a-to-many-{i}.txt')
print(f.read().replace('a-to-many', 'b-through'), end='')
