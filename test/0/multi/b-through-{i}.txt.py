from sys import argv

_, i = argv

f = open(f'a-to-many-{i}.txt')
print(f.read().replace('a-to-many', 'b-through'), end='')
