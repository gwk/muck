# Dedicated to the public domain under CC0: https://creativecommons.org/publicdomain/zero/1.0/.

import argparse
import re
from dataclasses import dataclass
from typing import Callable, DefaultDict, Dict, FrozenSet, Iterable, List, Match, NamedTuple, Optional, Set, Tuple

from .constants import *
from .db import DB
from .logging import error, note
from .pithy.format import FormatError, format_to_re, parse_formatters
from .pithy.fs import list_dir, norm_path, path_ext, path_join, path_name_stem, path_stem, split_dir_name
from .pithy.iterable import first_el


class Dependent(NamedTuple):
  kind: str # 'source', 'inferred', or 'observed'.
  target: str


class InvalidTarget(Exception):
  def __init__(self, target:str, msg:str) -> None:
    super().__init__(target, msg)
    self.target = target
    self.msg = msg


class TargetNotFound(Exception): pass


@dataclass
class TargetStatus:
  change_time: int = 0 # Logical (monotonic) time.
  error: Optional[Tuple[str, ...]] = None
  is_updated: bool = False


class Ctx(NamedTuple):
  args: argparse.Namespace
  db: DB
  build_dir: str
  build_dir_slash: str
  build_dir_abs: str
  fifo_path: str
  reserved_names: FrozenSet
  dbg: Callable[..., None]
  dbg_libmuck: bool
  statuses: Dict[str, TargetStatus] = {}
  dir_names: Dict[str, List[str]] = {}
  dependents: DefaultDict[str, Set[Dependent]] = DefaultDict(set)


  @property
  def targets(self) -> List[str]:
    return [norm_path(t) for t in self.args.targets]


  def is_product_path(self, path:str) -> bool:
    return path.startswith(self.build_dir_slash)


  def list_dir_filtered(self, src_dir:str) -> List[str]:
    '''
    Given src_dir, cache and return the list of names that might be source files.
    TODO: eventually this should be replaced by using os.scandir.
    '''
    try: return self.dir_names[src_dir]
    except KeyError: pass
    names = [n for n in list_dir(src_dir, hidden=False)
      if n not in self.reserved_names and path_ext(n) not in reserved_or_ignored_exts]
    self.dir_names[src_dir] = names
    return names


  def product_path_for_target(self, target:str) -> str:
    return path_join(self.build_dir, target)


  def reset(self) -> None:
    self.statuses.clear()
    self.dir_names.clear()
    self.dependents.clear()


  def source_for_target(self, target:str) -> str:
    '''
    Find the unique source path whose name matches `target`, or else error.
    '''
    src_dir, prod_name = split_dir_name(target)
    src_name = self.source_candidate(target, src_dir, prod_name)
    src = path_join(src_dir, src_name)
    assert src != target
    return src


  def source_candidate(self, target:str, src_dir:str, prod_name:str) -> str:
    src_dir = src_dir or '.'
    try: src_dir_names = self.list_dir_filtered(src_dir)
    except FileNotFoundError: raise error(target, f'no such source directory: `{src_dir}`')
    candidates = list(filter_source_names(src_dir_names, prod_name))
    if len(candidates) == 1:
      return candidates[0]
    # error.
    # Use dependent to describe error if possible; often the dependent code is naming something that does not exist.
    # TODO: use source locations wherever possible.
    dpdts = self.dependents[target]
    dpdt_name = first_el(dpdts).target if dpdts else target
    if len(candidates) == 0:
      raise TargetNotFound(dpdt_name, f'no source candidates matching `{target}` in `{src_dir}`')
    else:
      raise TargetNotFound(dpdt_name, f'multiple source candidates matching `{target}`: {candidates}')


  def target_for_product(self, product_path:str) -> str:
    'Return the target path for `product_path`.'
    assert self.is_product_path(product_path)
    return product_path[len(self.build_dir_slash):]


  def target_for_source(self, source_path:str) -> str:
    'Return the target path for `source_path` (which may itself be a product).'
    path = path_stem(source_path) # strip off source ext.
    if self.is_product_path(path): # source might be a product.
      return path[len(self.build_dir_slash):]
    else:
      return path


  def validate_target(self, target:str) -> None:
    if not target:
      raise InvalidTarget(target, 'empty string.')
    inv_m = target_invalids_re.search(target)
    if inv_m:
      if target.startswith('../_fetch/'): # TODO: this is a hack.
        return
      raise InvalidTarget(target, f'cannot contain {inv_m[0]!r}.')
    if target.startswith('-'):
      raise InvalidTarget(target, "cannot begin with '-'.")
    if target.startswith('.') or target.endswith('.'):
      raise InvalidTarget(target, "cannot begin or end with '.'.")
    if target == self.build_dir or self.is_product_path(target):
      raise InvalidTarget(target, f'target path is prefixed with build dir.')
    if path_name_stem(target) in self.reserved_names:
      reserved_desc = ', '.join(sorted(self.reserved_names))
      raise InvalidTarget(target, f'name is reserved; please rename the target.\n(reserved names: {reserved_desc}.)')
    if path_ext(target) in reserved_exts:
      raise InvalidTarget(target, 'target name has reserved extension; please rename the target.')
    try:
      for name, _, _, _t in parse_formatters(target):
        if not name:
          raise InvalidTarget(target, 'contains unnamed formatter')
    except FormatError as e:
      raise InvalidTarget(target, 'invalid format') from e


  def validate_target_or_error(self, target:str) -> None:
    try: self.validate_target(target)
    except InvalidTarget as e:
      exit(f'muck error: invalid target: {e.target!r}; {e.msg}')


target_invalids_re = re.compile(r'[\s]|\.\.|\./|//')


def filter_source_names(names:Iterable[str], prod_name:str) -> Iterable[str]:
  '''
  Given `prod_name`, find all matching source names.
  There are several concerns that make this matching complex.
  * Muck allows named formatters (e.g. '{x}') in script names.
    This allows a single script to produce many targets for corresponding arguments.
  * A source might itself be the product of another source.

  So, given product name "x.txt", match all of the following:
  * x.txt.py
  * {}.txt.py
  * x.txt.py.py
  * {}.txt.py.py
  '''
  prod = prod_name.split('.')
  for src_name in names:
    src = src_name.split('.')
    if len(src) <= len(prod): continue
    if all(match_wilds(*p) for p in zip(src, prod)): # zip stops when prod is exhausted.
      yield '.'.join(src[:len(prod)+1]) # the immediate source name has just one extension added.


def match_wilds(wildcard_path:str, string:str) -> Optional[Match[str]]:
  '''
  Match a string against a wildcard/format path.
  '''
  r = format_to_re(wildcard_path)
  return r.fullmatch(string)

_wildcard_re = re.compile(r'(%+)')
