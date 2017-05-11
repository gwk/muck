# Dedicated to the public domain under CC0: https://creativecommons.org/publicdomain/zero/1.0/.

'''
Muck constants.
'''

out_ext = '.out'
tmp_ext = '.tmp'
manifest_ext = '.tmp_manifest'

ignored_exts = frozenset({
  '.err', '.iot', '.out', '.expected', # iotest extensions.
})

reserved_exts = frozenset({
  out_ext,
  tmp_ext,
  manifest_ext,
})

reserved_or_ignored_exts = reserved_exts | ignored_exts
