# Dedicated to the public domain under CC0: https://creativecommons.org/publicdomain/zero/1.0/.

'''
Muck program constants.
'''


build_dir = '_build'
build_dir_slash = build_dir + '/'
db_name = '_muck'

ignored_exts = frozenset({
  '.err', '.iot', '.out', # iotest extensions.
})


reserved_exts = frozenset({
  '.tmp',
  '.tmp_manifest',
})

reserved_names = frozenset({
  'clean',
  'clean-all',
  'deps',
  'muck',
  'patch',
  build_dir,
  db_name,
})

