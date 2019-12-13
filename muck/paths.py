# Dedicated to the public domain under CC0: https://creativecommons.org/publicdomain/zero/1.0/.

'''
Muck target path functions.
'''

import re
from itertools import product
from os import chmod
from stat import S_ISVTX, S_IWGRP, S_IWOTH, S_IWUSR
from typing import Dict, Tuple

from .pithy.filestatus import file_permissions, is_sticky
from .pithy.format import parse_formatters
from .pithy.path import path_stem
from .pithy.string import pluralize


def is_target_product(path:str) -> bool:
  return is_sticky(path, follow=False) is not False # Target is a product if it does not exist, or if the sticky bit is set.


def dflt_prod_path_for_source(source_path:str) -> str:
  '''
  Return the default product path for `source_path` (which may itself be a product),
  as implied by the source stem.
  '''
  return path_stem(source_path) # strip off source ext.


def bindings_from_args(src:str, args:Tuple[str, ...]) -> Dict[str, str]:
  '''
  Return a dictionary pairing formatter names in `src` to argument values in `args`.'
  Requires that each formatter is named.
  '''
  formatters = list(parse_formatters(src))
  if len(formatters) != len(args):
    raise ValueError(f'format expects {pluralize(len(args), "arg")} args but was provided with {len(formatters)}')
  for i, (name, _, _, _t) in enumerate(formatters):
    if not name: raise ValueError(f'formatter {i} must specify a field name')
  return { name : type_(val) for (name, _, _, type_), val in zip(formatters, args) }


def dst_path(src:str, args:Tuple[str, ...], override_bindings:Dict[str, str]) -> str:
  base_bindings = bindings_from_args(src, args)
  bindings = base_bindings.copy()
  for k, v in override_bindings.items():
    if k not in bindings: raise Exception(f'source: {src}: binding does not match any field name: {k}')
    bindings[k] = v
  fmt = dflt_prod_path_for_source(src)
  try:
    return fmt.format(**bindings)
  except KeyError as e:
     raise Exception(f'format {fmt!r} requires field name {e.args[0]!r}; provided bindings: {bindings}') from e


def set_prod_perms(path:str, *, is_product:bool, is_patched:bool=False) -> None:
  old_perms = file_permissions(path, follow=False)
  readonly = old_perms & nonwriteable
  if is_product:
    new_perms = readonly | S_ISVTX
    if is_patched:
      new_perms = new_perms | user_writeable
  else:
    new_perms = (readonly & ~S_ISVTX) | user_writeable
  chmod(path, new_perms, follow_symlinks=False)


user_writeable = S_IWUSR
nonwriteable = ~(S_IWGRP|S_IWOTH|S_IWUSR)
