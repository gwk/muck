# Dedicated to the public domain under CC0: https://creativecommons.org/publicdomain/zero/1.0/.

'''
Muck target path functions.
'''

import re
from itertools import product
from .pithy.format import FormatError, count_formatters, format_partial, has_formatter, format_to_re, parse_formatters
from .pithy.fs import path_exists, path_ext, path_join, path_name_stem, path_stem
from .pithy.string_utils import pluralize
from .constants import build_dir, build_dir_slash, manifest_ext, reserved_exts, reserved_names, reserved_or_ignored_exts
from typing import *


class InvalidTarget(Exception):
  def __init__(self, target, msg):
    super().__init__(target, msg)
    self.target = target
    self.msg = msg


target_invalids_re = re.compile(r'[\s]|\.\.|\./|//')

def validate_target(target):
  if not target:
    raise InvalidTarget(target, 'empty string.')
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
  try:
    for name, _, _ in parse_formatters(target):
      if not name:
        raise InvalidTarget(target, 'contains unnamed formatter')
  except FormatError as e:
    raise InvalidTarget(target, 'invalid format') from e


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
  Match a string against a wildcard/format path.
  '''
  r = format_to_re(wildcard_path)
  return r.fullmatch(string)


def manifest_path(argv):
  return dst_path(argv, override_bindings={}) + manifest_ext


def bindings_for_format(format_path, kwargs):
  '''
  Parse `format_path` field names and yield (name, arg) pairs,
  where `arg` is pulled from `kwargs`.
  '''
  for name, _, _ in parse_formatters(format_path):
    try: arg = kwargs[name]
    except KeyError as e: raise Exception(f'missing argument for formatter field {name}') from e
    yield name, arg


def paths_from_format(format_path: str, seqs: Dict[str, Sequence], partial=False) \
 -> Iterable[Tuple[str, Dict[str, str]]]:
  '''
  Generate paths from the format path and matching argument sequences.
  '''
  # note: relies on python3.6 keys() and values() having the same order.
  for vals in product(*seqs.values()):
    args = dict(zip(seqs.keys(), vals))
    if partial:
      yield format_partial(format_path, **args), args
    else:
      try:
        yield format_path.format(**args), args
      except KeyError as e:
        raise Exception(f'format {format_path!r} requires field name {e.args[0]!r}; provided args: {args}') from e


def bindings_from_argv(argv: Sequence[str]) -> Dict[str, str]:
  '''
  Given `argv`, return a dictionary pairing formatter names to argument values.'
  Requires that each formatter is named.
  '''
  fmt = argv[0]
  args = argv[1:]
  formatters = list(parse_formatters(fmt))
  if len(formatters) != len(args):
    raise ValueError(f'format expects {pluralize(len(args), "arg")} args but was provided with {len(formatters)}')
  for i, (name, _, _) in enumerate(formatters):
    if not name: raise ValueError(f'formatter {i} must specify a field name')
  return { name : val for (name, _, _), val in zip(formatters, args) }


def dst_path(argv, override_bindings):
  src = argv[0]
  base_bindings = bindings_from_argv(argv)
  bindings = base_bindings.copy()
  for k, v in override_bindings.items():
    if k not in bindings: raise Exception(f'source: {src}: binding does not match any field name: {k}')
    bindings[k] = v
  fmt = product_path_for_source(src)
  try:
    return fmt.format(**bindings)
  except KeyError as e:
     raise Exception(f'format {fmt!r} requires field name {e.args[0]!r}; provided bindings: {bindings}') from e

