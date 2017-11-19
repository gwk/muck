# Dedicated to the public domain under CC0: https://creativecommons.org/publicdomain/zero/1.0/.

'''
Muck constants.
'''


old_ext = '.old'
out_ext = '.out'
tmp_ext = '.tmp'

ignored_exts = frozenset({
  '.err', '.iot', '.out', '.expected', # iotest extensions.
})

reserved_exts = frozenset({
  old_ext,
  out_ext,
  tmp_ext,
})

reserved_or_ignored_exts = reserved_exts | ignored_exts
