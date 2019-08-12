# Dedicated to the public domain under CC0: https://creativecommons.org/publicdomain/zero/1.0/.

import argparse
import re
from dataclasses import dataclass, field
from os import getpid
from typing import (Any, Callable, DefaultDict, Dict, FrozenSet, Iterable, Iterator, List, Match, NamedTuple, Optional, Pattern,
  Set, Tuple)

from .constants import *
from .db import DB
from .logging import error_msg, note
from .pithy.format import FormatError, count_formatters, format_to_re, has_formatter, parse_formatters
from .pithy.fs import (DirEntries, DirEntry, file_status, is_link_to_dir, list_dir, make_dir, make_link, norm_path, path_exists,
  path_ext, path_join, path_name_stem, path_stem, read_link, split_dir_name)
from .pithy.iterable import first_el


class BuildError(Exception):
  def __init__(self, target:str, *msg:Any) -> None:
    super().__init__(target, *msg)
    self.target = target
    self.msg = msg

  def __str__(self) -> str:
    return error_msg(*self.args)


class InvalidTarget(BuildError):
  def __str__(self) -> str:
    return f'muck error: invalid target: {self.target!r}; ' + ''.join(str(m) for m in self.msg)


class TargetNotFound(BuildError): pass


OptDpdt = Optional[Any] # TODO: 'Dpdt'

class Dpdt(NamedTuple):
  '''
  Dependent target tracking.
  Each recursive update creates a `Dpdt`, forming a linked list of targets.
  These are used for reporting circular dependency errors,
  and for rendering dependency tree info.
  TODO: make kind an enum.
  '''
  kind:str # 'source', 'inferred', or 'observed'.
  target:str
  parent:OptDpdt

  def __str__(self) -> str:
    return f'Dpdt: {self.target} ({self.kind})'

  def sub(self, kind:str, target:str) -> 'Dpdt':
    return Dpdt(kind=kind, target=target, parent=self)

  def cycle(self, target:str) -> Iterator[str]:
    'Yield the sequence of targets creating a dependency cycle.'
    yield target
    current:OptDpdt = self
    while current is not None:
      yield current.target
      if current.target == target: return
      current = current.parent
    yield '<ACYCLIC?>'


@dataclass
class TargetStatus:
  dpdt:Dpdt
  expected:bool
  change_time: int = 0 # Logical (monotonic) time.
  error: Optional[BuildError] = None
  is_updated: bool = False


@dataclass
class CtxState:
  has_fetch_dirs = False
  reserved_prefixes_pattern: Pattern = re.compile('')

@dataclass(frozen=True)
class Ctx:
  args: argparse.Namespace
  db: DB
  proj_dir: str
  build_dir: str
  build_dir_slash: str
  build_dir_abs: str
  fifo_path: str
  reserved_names: FrozenSet
  reserved_prefixes: Tuple[str,...]
  dbg: Callable
  dbg_child: bool
  dbg_child_lldb: List[str]
  statuses: Dict[str, TargetStatus] = field(default_factory=dict)
  dir_entries: DirEntries = field(default_factory=DirEntries)
  dependents: DefaultDict[str, Set[Dpdt]] = field(default_factory=lambda:DefaultDict(set))
  pid_str: str = str(getpid())
  fetch_dir = '_fetch' # Currently a constant to match pithy.fetch.
  state: CtxState = field(default_factory=CtxState)

  def __post_init__(self) -> None:
    self.dir_entries.hidden = False
    reserved_names = self.reserved_names # Do not create circular reference between self and pred.
    self.dir_entries.pred = lambda entry: \
      entry.is_file() and (entry.name not in reserved_names and path_ext(entry.name) not in reserved_or_ignored_exts)
    self.state.reserved_prefixes_pattern = re.compile('(' + f'|'.join(self.reserved_prefixes) + ')')


  def reset(self) -> None:
    self.statuses.clear()
    self.dir_entries.clear()
    self.dependents.clear()
    self.state.has_fetch_dirs = False

  @property
  def targets(self) -> List[str]:
    return [norm_path(t) for t in self.args.targets]


  def create_fetch_dirs(self) -> None:
    if self.state.has_fetch_dirs: return
    self.state.has_fetch_dirs = True

    s = file_status(self.fetch_dir, follow=False)
    if not s: make_dir(self.fetch_dir)
    elif not s.is_dir:
      exit(f'muck fatal error: fetch directory {self.fetch_dir} exists but is not a directory.')

    fetch_link = path_join(self.build_dir, self.fetch_dir)
    s = file_status(fetch_link, follow=False)
    if not s: make_link(self.fetch_dir, link=fetch_link)
    else:
      if not s.is_link:
        exit(f'muck fatal error: fetch directory link {fetch_link} exists but is not a symlink.')
      dst = read_link(fetch_link)
      if dst != self.fetch_dir:
        exit(f'muck fatal error: fetch directory link {fetch_link} exists but points to the wrong location: {dst}.')


  def is_product_path(self, path:str) -> bool:
    return path.startswith(self.build_dir_slash)


  def product_path_for_target(self, target:str) -> str:
    return path_join(self.build_dir, target)


  def source_for_target(self, target:str, dpdt:Dpdt) -> str:
    '''
    Find the unique source path whose name matches `target`, or else error.
    '''
    src_dir, target_name = split_dir_name(target)
    src_name = self.source_candidate(target, src_dir, target_name, dpdt)
    src = path_join(src_dir, src_name)
    assert src != target
    return src


  def source_candidate(self, target:str, src_dir:str, target_name:str, dpdt:Dpdt) -> str:
    src_dir = src_dir or '.'
    try: entries = self.dir_entries[src_dir]
    except FileNotFoundError: raise BuildError(target, f'no such source directory: `{src_dir}`')
    req_exact = (dpdt.kind == 'directory contents')
    candidates = filter_source_candidates(entries=entries, target_name=target_name, req_exact=req_exact)
    # Check for errors. Use the dependent to describe the error;
    # usually the dependent is requesting something that does not exist.
    # TODO: use source locations wherever possible.
    dpdt_name = dpdt.target or target
    if len(candidates) == 0:
      raise TargetNotFound(dpdt_name, f'no source candidates matching `{target}` in `{src_dir}`')
    if len(candidates) > 1:
      candidates.sort()
      raise TargetNotFound(dpdt_name, f'multiple source candidates matching `{target}`: {candidates}')
    return candidates[0]


  def target_for_product(self, product_path:str) -> str:
    'Return the target path for `product_path`.'
    assert self.is_product_path(product_path)
    return product_path[len(self.build_dir_slash):]


  def target_for_source(self, source_path:str) -> str:
    'Return the target path for `source_path` (which may itself be a product).'
    return self.strip_opt_build_dir(path_stem(source_path)) # strip off source ext, then possibly strip leading build_dir.


  def strip_opt_build_dir(self, path:str) -> str:
    if self.is_product_path(path):
      return path[len(self.build_dir_slash):]
    else:
      return path


  def validate_target(self, target:str) -> None:
    if not target:
      raise InvalidTarget(target, 'empty string.')
    inv_m = target_invalids_re.search(target)
    if inv_m:
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
      raise InvalidTarget(target, 'name has a reserved extension; please rename the target.')
    if self.state.reserved_prefixes_pattern.match(target):
      reserved_desc = ', '.join(sorted(self.reserved_prefixes))
      raise InvalidTarget(target, 'name has a reserved prefix; please rename the target.\n'
        f'(reserved prefixes: {reserved_desc}.)')
    try:
      for name, _, _, _t in parse_formatters(target):
        if not name:
          raise InvalidTarget(target, 'contains unnamed formatter')
    except FormatError as e:
      raise InvalidTarget(target, 'invalid format') from e


  def validate_target_or_exit(self, target:str) -> None:
    try: self.validate_target(target)
    except InvalidTarget as e: exit(e)


target_invalids_re = re.compile(r'''(?x)
  [\x00-\x1f\x7f-\x9f] # Ascii and Latin-1 control characters.
| \s
| \.\./
| \./
| //
''')


def filter_source_candidates(entries:Iterable[DirEntry], target_name:str, req_exact:bool) -> List[str]:
  '''
  Given `target_name`, find all matching source names.
  There are several concerns that make this matching complex.
  * Muck allows named formatters (e.g. '{x}') in script names.
    This allows a single script to produce many products for corresponding arguments.
  * A source might itself be the product of another source.

  So, given target name "x.txt", match all of the following:
  * x.txt.py
  * {}.txt.py
  * x.txt.py.py
  * {}.txt.py.py
  '''
  candidates = []

  if req_exact:
    for entry in entries:
      name = entry.name
      stem = path_stem(name)
      if stem == target_name:
        candidates.append(name)

  else: # Allow formatter names to match.
    # Note: naive splitting by '.' means that formats containing '.' will be broken.
    target = target_name.split('.')
    for entry in entries:
      name = entry.name
      src = name.split('.')
      if len(src) <= len(target): continue # src must have more components than target.
      if all(match_format(*p) for p in zip(src, target)): # zip stops when target is exhausted.
        candidates.append('.'.join(src[:len(target)+1])) # The immediate source name has just one extension added.

    if len(candidates) > 1: # Attempt to reduce candidates by minimum wildcards.
      cand_fmt_counts = [(cand, count_formatters(cand)) for cand in candidates]
      min_count = min(count for _, count in cand_fmt_counts)
      candidates = [cand for cand, count in cand_fmt_counts if count == min_count]

  return candidates



def match_format(format:str, string:str) -> Optional[Match[str]]:
  '''
  Match a string against a wildcard/format path.
  '''
  r = format_to_re(format)
  return r.fullmatch(string)
