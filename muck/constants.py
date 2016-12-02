# Dedicated to the public domain under CC0: https://creativecommons.org/publicdomain/zero/1.0/.

'''
Muck program constants.
'''


build_dir = '_build'
build_dir_slash = build_dir + '/'
db_name = '_muck'
db_path = build_dir_slash + db_name

out_ext = '.out'
tmp_ext = '.tmp'
manifest_ext = '.tmp_manifest'

ignored_exts = frozenset({
  '.err', '.iot', '.out', # iotest extensions.
})


reserved_exts = frozenset({
  out_ext,
  tmp_ext,
  manifest_ext,
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

