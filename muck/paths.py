# Dedicated to the public domain under CC0: https://creativecommons.org/publicdomain/zero/1.0/.

'''
Muck target path functions.
'''

import re
from itertools import product
from .pithy.format import count_formatters, has_formatter, format_to_re
from .pithy.fs import path_exists, path_ext, path_join, path_name_stem, path_stem
from .constants import build_dir, build_dir_slash, manifest_ext, reserved_exts, reserved_names, reserved_or_ignored_exts


class InvalidTarget(Exception):
  def __init__(self, target, msg):
    super().__init__(target, msg)
    self.target = target
    self.msg = msg


target_invalids_re = re.compile(r'[\s]|\.\.|\./|//')

def validate_target(target):
  if not target:
    raise InvalidTarget(target, f'empty string.')
  inv_m  =target_invalids_re.search(target)
  if inv_m:
    raise InvalidTarget(target, f'cannot contain {inv_m.group(0)!r}.')
  if target[0] == '.' or target[-1] == '.':
    raise InvalidTarget(target, "cannot begin or end with '.'.")
  if path_name_stem(target) in reserved_names:
    reserved_desc = ', '.join(sorted(reserved_names))
    raise InvalidTarget(target, f'name is reserved; please rename the target.\n(reserved names: {reserved_desc}.)')
  if path_ext(target) in reserved_exts:
    raise InvalidTarget(target, 'target name has reserved extension; please rename the target.')


def validate_target_or_error(target):
  try: validate_target(target)
  except InvalidTarget as e:
    exit(f'muck error: invalid target: {e.target!r}; {e.msg}')


def is_product_path(path):
  return path.startswith(build_dir_slash)


def actual_path_for_target(target_path):
  '''
  returns the target_path if it exists (indicating that it is a source file),
  or else the corresponding product path.
  '''
  if path_exists(target_path):
    return target_path
  return product_path_for_target(target_path)


def product_path_for_target(target_path):
  if target_path == build_dir or is_product_path(target_path):
    raise ValueError(f'provided target path is prefixed with build dir: {target_path}')
  return path_join(build_dir, target_path)


def product_path_for_source(source_path):
  'Retern the product path for `sourc_path` (which may itself be a product).'
  path = path_stem(source_path) # strip off source ext.
  if is_product_path(path): # source might be a product.
    return path
  else:
    return path_join(build_dir, path)


def target_path_for_source(source_path):
  'Return the target path for `source_path` (which may itself be a product).'
  path = path_stem(source_path) # strip off source ext.
  if is_product_path(path): # source might be a product.
    return path[len(build_dir_slash):]
  else:
    return path


_wildcard_re = re.compile(r'(%+)')

def match_wilds(wildcard_path, string):
  '''
  Match a string against a wildcard path.
  The muck wildcard character is '%'.
  This character was chosen because bash treats it as a plain char.
  Consecutive wilds indicate required padding.
  '''
  r = format_to_re(wildcard_path)
  return r.fullmatch(string)


def manifest_path(argv):
  return dst_path(argv, argv[1:], strict=False) + manifest_ext


def format_args(format_path, args):
  count = count_formatters(format_path)
  if len(args) != count:
    raise ValueError(f'format path has {count} formatters; received {len(args)} args: {format_path}')
  return format_path.format(*args)


def pad_sub(wildcard, var):
  width = len(wildcard)
  if isinstance(var, int):
    return f'{var:0{width}}'
  else:
    return f'{var:_<{width}}'


def paths_from_format_seqs(format_path, seqs):
  for args in product(*seqs):
    yield args, format_args(format_path, args)


def dst_path(argv, vars, strict=True):
  src = argv[0]
  args = argv[1:]

  class Error(Exception):
    def __init__(self, msg):
      super().__init__((f'source: {src}; args: {args}; vars: {vars}; {msg}'))

  if len(vars) != len(args):
    raise Error(f'expected {len(vars)} vars; received {len(args)}')

  subs = []
  for i, (a, v) in enumerate(zip(args, vars), 1):
    if isinstance(v, str) and has_formatter(v):
      if strict and has_formatter(a):
        raise Error(f'arg {i}: both arg and var are format strings.')
      subs.append(a)
    else:
      subs.append(v)
  return format_args(product_path_for_source(src), args=subs)
