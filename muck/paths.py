# Dedicated to the public domain under CC0: https://creativecommons.org/publicdomain/zero/1.0/.

'''
Muck target path functions.
'''

from os import chmod
from stat import S_IWGRP, S_IWOTH, S_IWUSR
from typing import Dict, Tuple

from xattr import getxattr as get_xattr, removexattr as remove_xattr, setxattr as set_xattr

from .ctx import BuildError
from .logging import warn
from .pithy.filestatus import file_permissions, file_perms_desc, perms_desc
from .pithy.format import parse_formatters
from .pithy.fs import path_exists
from .pithy.path import path_stem
from .pithy.string import pluralize


_muck_xattr_key = 'muck.product'


def is_muck_product(path:str) -> bool:
  try: get_xattr(path, _muck_xattr_key, symlink=False)
  except IOError: return False
  else: return True


def set_is_muck_product(path:str, is_product:bool) -> None:
  try:
    if is_product:
      set_xattr(path, _muck_xattr_key, b'')
    else:
      remove_xattr(path, _muck_xattr_key)
  except IOError as e:
    try: desc = file_perms_desc(path)
    except Exception: desc = 'unknown'
    raise BuildError(path, f'set_is_muck_product: permission denied: {desc}') from e



def is_target_product(path:str) -> bool:
  'Target is a product if it does not exist, or if the muck.product xattr is set.'
  return not path_exists(path, follow=False) or is_muck_product(path)


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
  '''
  Modify the permissions of the file at `path` to reflect its product status.
  If it is a product, the file is made read-only and the 'muck.product' xattr is set.
  If it is not a product, the file is made user-writeable and the 'muck.product' xattr is cleared.
  '''
  old_perms = file_permissions(path, follow=False)
  readonly = old_perms & _nonwriteable
  if is_product and not is_patched:
    new_perms = readonly
  else:
    new_perms = readonly | _user_writeable
  if not (old_perms & _user_writeable):
    chmod(path, old_perms | _user_writeable, follow_symlinks=False)
  set_is_muck_product(path, is_product=is_product)
  chmod(path, new_perms, follow_symlinks=False)


def set_write_perm(path:str) -> None:
  '''
  Modify the permissions of the file at `path` to make it user-writeable.
  If the file does not exist, do nothing.
  '''
  try: old_perms = file_permissions(path, follow=False)
  except FileNotFoundError: return
  if old_perms & _user_writeable: return # Already set.
  if not is_muck_product(path): # Not marked as a product; we should not alter write permissions.
    warn(path, 'not a product; refusing to alter write permissions.')
    return
  new_perms = old_perms | _user_writeable
  chmod(path, new_perms, follow_symlinks=False)


_user_writeable = S_IWUSR
_nonwriteable = ~(S_IWGRP|S_IWOTH|S_IWUSR)
