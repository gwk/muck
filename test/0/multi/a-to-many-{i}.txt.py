
for i in range(2):
  with open(f'a-to-many-{i}.txt', 'w') as f:
    print('a-to-many', i, file=f)
