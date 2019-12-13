# Dedicated to the public domain under CC0: https://creativecommons.org/publicdomain/zero/1.0/.

'''
Muck constants.
'''


muck_out_ext = '.muck_out'
muck_tmp_ext = '.tmp'

ignored_exts = frozenset({
  '.err', '.iot', '.out', '.expected', # iotest extensions.
})

reserved_exts = frozenset({
  muck_out_ext,
  muck_tmp_ext,
})

reserved_or_ignored_exts = reserved_exts | ignored_exts
