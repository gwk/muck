# Dedicated to the public domain under CC0: https://creativecommons.org/publicdomain/zero/1.0/.

'''
Muck target path functions.
'''

import re
from itertools import product
from .pithy.format import format_partial, parse_formatters
from .pithy.fs import path_stem
from .pithy.string_utils import pluralize
from .constants import manifest_ext
from typing import *


def dflt_prod_path_for_source(source_path: str) -> str:
  '''
  Return the default product path for `source_path` (which may itself be a product),
  as implied by the source stem.
  '''
  return path_stem(source_path) # strip off source ext.


def manifest_path(argv: List[str]) -> str:
  return dst_path(argv, override_bindings={}) + manifest_ext


def bindings_for_format(format_path: str, kwargs: Dict[str, Sequence]) -> Iterable[Tuple[str, Sequence]]:
  '''
  Parse `format_path` field names and yield (name, seq) pairs,
  where `seq` is pulled from `kwargs`.
  '''
  for name, _, _, _t in parse_formatters(format_path):
    try: arg = kwargs[name]
    except KeyError as e: raise Exception(f'missing argument for formatter field {name!r} in path: {format_path!r}') from e
    yield name, arg


def paths_from_format(format_path: str, seqs: Dict[str, Sequence], partial=False) -> Iterable[Tuple[str, Dict[str, Any]]]:
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


def bindings_from_argv(argv: List[str]) -> Dict[str, str]:
  '''
  Given `argv`, return a dictionary pairing formatter names to argument values.'
  Requires that each formatter is named.
  '''
  fmt = argv[0]
  args = argv[1:]
  formatters = list(parse_formatters(fmt))
  if len(formatters) != len(args):
    raise ValueError(f'format expects {pluralize(len(args), "arg")} args but was provided with {len(formatters)}')
  for i, (name, _, _, _t) in enumerate(formatters):
    if not name: raise ValueError(f'formatter {i} must specify a field name')
  return { name : type_(val) for (name, _, _, type_), val in zip(formatters, args) }


def dst_path(argv: List[str], override_bindings: Dict[str, str]) -> str:
  src = argv[0]
  base_bindings = bindings_from_argv(argv)
  bindings = base_bindings.copy()
  for k, v in override_bindings.items():
    if k not in bindings: raise Exception(f'source: {src}: binding does not match any field name: {k}')
    bindings[k] = v
  fmt = dflt_prod_path_for_source(src)
  try:
    return fmt.format(**bindings)
  except KeyError as e:
     raise Exception(f'format {fmt!r} requires field name {e.args[0]!r}; provided bindings: {bindings}') from e

