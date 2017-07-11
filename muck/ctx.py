# Dedicated to the public domain under CC0: https://creativecommons.org/publicdomain/zero/1.0/.

import argparse
import re
from typing import *
from .pithy.format import FormatError, parse_formatters

from .pithy.fs import path_join, path_ext, path_name_stem
from .constants import *
from .db import DB


class Ctx(NamedTuple):
  args: argparse.Namespace
  db: DB
  build_dir: str
  build_dir_slash: str
  reserved_names: FrozenSet
  report_times: bool
  dbg: Callable[..., None]
  change_times: Dict[str, Optional[int]] = {}
  dir_names: Dict[str, List[str]] = {}
  dependents: DefaultDict[str, Set[str]] = DefaultDict(set)

  def is_product_path(self, path: str) -> bool:
    return path.startswith(self.build_dir_slash)

  def product_path_for_target(self, target: str) -> str:
    return path_join(self.build_dir, target)

  def reset(self) -> None:
    self.change_times.clear()
    self.dir_names.clear()
    self.dependents.clear()


class InvalidTarget(Exception):
  def __init__(self, target: str, msg: str) -> None:
    super().__init__(target, msg)
    self.target = target
    self.msg = msg


target_invalids_re = re.compile(r'[\s]|\.\.|\./|//')

def validate_target(ctx: Ctx, target: str) -> None:
  if not target:
    raise InvalidTarget(target, 'empty string.')
  inv_m  =target_invalids_re.search(target)
  if inv_m:
    raise InvalidTarget(target, f'cannot contain {inv_m[0]!r}.')
  if target[0] == '.' or target[-1] == '.':
    raise InvalidTarget(target, "cannot begin or end with '.'.")
  if target == ctx.build_dir or ctx.is_product_path(target):
    raise InvalidTarget(target, f'target path is prefixed with build dir.')
  if path_name_stem(target) in ctx.reserved_names:
    reserved_desc = ', '.join(sorted(ctx.reserved_names))
    raise InvalidTarget(target, f'name is reserved; please rename the target.\n(reserved names: {reserved_desc}.)')
  if path_ext(target) in reserved_exts:
    raise InvalidTarget(target, 'target name has reserved extension; please rename the target.')
  try:
    for name, _, _, _t in parse_formatters(target):
      if not name:
        raise InvalidTarget(target, 'contains unnamed formatter')
  except FormatError as e:
    raise InvalidTarget(target, 'invalid format') from e
