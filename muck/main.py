# Dedicated to the public domain under CC0: https://creativecommons.org/publicdomain/zero/1.0/.

'''
Muck is a build tool that infers dependencies between files.
'''

import sys
assert sys.version_info >= (3, 6, 0)

import base64
import json
import os
import shlex
import time

from argparse import ArgumentParser
from collections import defaultdict, namedtuple
from hashlib import sha256
from typing import *
from typing import BinaryIO, Match, TextIO

from .pithy.format import FormatError, has_formatter, format_to_re, parse_formatters
from .pithy.fs import *
from .pithy.io import *
from .pithy.iterable import fan_by_pred
from .pithy.json_utils import load_json, write_json
from .pithy.string_utils import format_byte_count
from .pithy.task import runC

from .db import TargetRecord, empty_record, is_empty_record, DB, DBError
from .constants import *
from .paths import *
from .py_deps import py_dependencies


def main() -> None:
  arg_parser = ArgumentParser(description=__doc__)
  arg_parser.add_argument('targets', nargs='*', default=[], help="target file names; defaults to 'index.html'.")
  arg_parser.add_argument('-no-times', action='store_true', help='do not report process times.')
  arg_parser.add_argument('-dbg', action='store_true', help='log lots of details to stderr.')
  arg_parser.add_argument('-force', action='store_true', help='rebuild specified targets even if they are up to date.')
  arg_parser.add_argument('-build-dir', default='_build', help="specify build directory; defaults to '_build'.")

  group = arg_parser.add_argument_group('special commands')
  def add_cmd(cmd: str, help: str) -> None:
    group.add_argument('-' + cmd, dest='cmds', action='append_const', const=cmd, help=help)

  add_cmd('clean', help='clean the specified targets or the entire build folder.')
  add_cmd('deps',  help='print targets and their dependencies as a visual hierarchy.')
  add_cmd('deps-list',  help='print targets and their dependencies as a list.')
  add_cmd('prod-list',  help='print products as a list.')
  add_cmd('patch', help='create a patch; usage: [original] [modified.pat]')
  add_cmd('update-patch', help='update a patch: usage: [target.pat]')

  args = arg_parser.parse_args()
  cmds = args.cmds or []
  build_dir = args.build_dir.rstrip('/')
  build_dir_slash = build_dir + '/'
  db_name = '_muck'
  db_path = build_dir_slash + db_name

  if args.dbg:
    def dbg(path: str, *items: str) -> None:
      errL(f'muck dbg: {path}: ', *items)
  else:
    def dbg(path: str, *items: str) -> None: pass

  if len(cmds) > 1:
    desc = ', '.join(repr('-' + c) for c in cmds)
    exit(f'muck error: multiple commands specified: {desc}.')

  make_dirs(build_dir) # required to create new DB.

  cmd = cmds[0] if cmds else None
  if cmd == 'clean' and not args.targets:
    muck_clean_all(build_dir)
    exit()

  reserved_names = frozenset({
    'muck',
    build_dir,
    db_name,
  })

  ctx = Ctx(db=DB(path=db_path), statuses={}, dir_names={}, dependents=defaultdict(set),
    build_dir=build_dir, build_dir_slash=build_dir_slash,
    reserved_names=reserved_names, report_times=(not args.no_times), dbg=dbg)

  for t in args.targets: validate_target_or_error(ctx, t)

  if cmd:
    command_fns[cmd](ctx, args.targets)
    return
  else: # no command; default behavior is to update each specified target.
    for target in (args.targets or ['index.html']):
      if path_exists(target):
        stem, ext = split_stem_ext(target)
        if ext in dependency_fns:
          note(target, f'specified target is a source and not a product; building {stem!r}...')
          target = stem
        else:
          note(target, 'specified target is a source and not a product.')
      update_dependency(ctx, target, dependent=None, force=args.force)



Ctx = namedtuple('Ctx', 'db statuses dir_names dependents build_dir build_dir_slash reserved_names report_times dbg')
# db: DB.
# statuses: dict (target: str => is_changed: bool|Ellipsis).
# dir_names: dict (dir_path: str => names: [str]).
# dependents: defaultdict(set) (target: str => depedents).
# report_times: bool.
# dbg: debug printing function.


# Commands.


def muck_clean_all(build_dir: str) -> None:
  '`muck -clean` command (no arguments).'
  remove_dir_contents(build_dir)


def muck_clean(ctx: Ctx, args: List[str]) -> None:
  '`muck -clean [targets...]` command.'
  assert args
  for target in args:
    if not ctx.db.contains_record(target=target):
      errL(f'muck clean note: {target}: skipping unknown target.')
      continue
    prod_path = product_path_for_target(ctx, target)
    remove_file_if_exists(prod_path)
    ctx.db.delete_record(target=target)


def muck_deps(ctx: Ctx, targets: List[str]) -> None:
  '`muck -deps [targets...]` command.'
  if not targets: targets = ['index.html']

  for target in sorted(targets):
    update_dependency(ctx, target, dependent=None)

  roots = set(targets)
  roots.update(t for t, s in ctx.dependents.items() if len(s) > 1)

  def visit(depth: int, target: str) -> None:
    record = ctx.db.get_record(target)
    dependents = ctx.dependents[target]
    src = record.src
    deps = record.deps
    wilds = record.wild_deps
    some = bool(src) or bool(deps) or bool(wilds)
    if depth == 0 and len(dependents) > 0:
      suffix = f' (dependents: {" ".join(sorted(dependents))}):'
    elif len(dependents) > 1: suffix = '*'
    elif some: suffix = ':'
    else: suffix = ''
    outL('  ' * depth, target, suffix)
    if depth > 0 and len(dependents) > 1: return
    for wild in wilds:
      outL('  ' * depth, ' ~', wild)
    if src is not None:
      visit(depth + 1, src)
    for dep in deps:
      visit(depth + 1, dep)
    for sub_dep in expanded_wild_deps(ctx, target, src):
      visit(depth + 1, sub_dep)

  for root in sorted(roots):
    outL()
    visit(0, root)


def muck_deps_list(ctx: Ctx, targets: List[str]) -> None:
  '`muck -deps-list [targets...]` command.'
  if not targets: targets = ['index.html']

  for target in sorted(targets):
    update_dependency(ctx, target, dependent=None)

  outLL(*sorted(ctx.statuses))


def muck_prod_list(ctx: Ctx, targets: List[str]) -> None:
  '`muck -deps-list [targets...]` command.'
  if not targets: targets = ['index.html']

  for target in sorted(targets):
    update_dependency(ctx, target, dependent=None)

  outLL(*sorted(product_path_for_target(ctx, t) for t in ctx.statuses))


def muck_create_patch(ctx: Ctx, args: List[str]) -> None:
  '`muck -patch` command.'
  if len(args) != 2:
    exit('''\
muck -patch error: requires two arguments: [original] [modified].
This command creates an empty patch called [modified].pat, and copies [original] to _build/[modified].''')
  original, modified = args
  patch = modified + '.pat'
  if original.endswith('.pat'):
    exit(f"muck -patch error: 'original' should not be a patch file: {original}")
  if modified.endswith('.pat'):
    exit(f"muck -patch error: 'modified' should not be a patch file: {modified}")
  if path_exists(modified) or ctx.db.contains_record(patch):
    exit(f"muck -patch error: 'modified' is an existing target: {modified}")
  if path_exists(patch) or ctx.db.contains_record(patch):
    exit(f"muck -patch error: patch is an existing target: {patch}")
  update_dependency(ctx, original, dependent=None)
  cmd = ['pat', 'create', original, modified, '../' + patch]
  cmd_str = ' '.join(shlex.quote(w) for w in cmd)
  errL(f'muck -patch note: creating patch: `{cmd_str}`')
  exit(runC(cmd, cwd=ctx.build_dir))


def muck_update_patch(ctx: Ctx, args: List[str]) -> None:
  '`muck -update-patch` command.'
  if len(args) != 1:
    exit('''\
muck -update-patch error: requires one argument, the patch target to update.
The patch file will be updated with the diff of the previously specified original and _build/[target].''')
  patch_path = args[0]
  if path_ext(patch_path) != '.pat':
    exit(f'muck -update-patch error: argument does not specify a .pat file: {patch_path!r}')
  deps = pat_dependencies(patch_path, open(patch_path), {})
  assert len(deps) == 1
  orig_path = deps[0]
  update_dependency(ctx, orig_path, dependent=None)
  target = path_stem(patch_path)
  patch_path_tmp = patch_path + tmp_ext
  cmd = ['pat', 'diff', orig_path, target, '../' + patch_path_tmp]
  cmd_str = ' '.join(shlex.quote(w) for w in cmd)
  errL(f'muck -update-patch note: diffing: `{cmd_str}`')
  code = runC(cmd, cwd=ctx.build_dir)
  if code: exit(code)
  move_file(patch_path_tmp, patch_path, overwrite=True)
  ctx.db.delete_record(target=target) # no-op if does not exist.
  #^ need to remove or update the target record to avoid the 'did you mean to patch?' safeguard.
  #^ for now, just delete it to be safe; this makes the target look stale.
  #^ TODO: update target instead.


command_fns: Dict[str, Callable[[Ctx, List[str]], None]] = {
  'clean'         : muck_clean,
  'deps'          : muck_deps,
  'deps-list'     : muck_deps_list,
  'patch'         : muck_create_patch,
  'prod-list'     : muck_prod_list,
  'update-patch'  : muck_update_patch,
}


# Default update functionality.


def update_dependency(ctx: Ctx, target: str, dependent: Optional[str], force=False) -> bool:
  '''
  returns is_changed.
  '''
  validate_target(ctx, target)

  if dependent is not None:
    ctx.dependents[target].add(dependent)

  try: status: Optional[bool] = ctx.statuses[target]
  except KeyError: pass
  else: # if in ctx.statuses, this path has already been visited during this build process run.
    if status is None: # recursion sentinal.
      involved_paths = sorted(path for path, status in ctx.statuses.items() if status is None)
      raise error(target, 'target has circular dependency; involved paths:', *('\n  ' + p for p in involved_paths))
    return status

  ctx.statuses[target] = None # recursion sentinal is replaced before return by update_deps_and_record.

  ctx.dbg(target, f'examining... (dependent={dependent})')
  is_product = not path_exists(target)
  if is_product and is_link(target):
    raise error(target, f'target is a dangling symlink to: {read_link(target)}')
  actual_path = product_path_for_target(ctx, target) if is_product else target
  size, mtime, old = calc_size_mtime_old(ctx, target, actual_path)
  has_old_file = (mtime > 0)
  has_old_record = not is_empty_record(old)

  is_changed = force or (not has_old_file) or (not has_old_record)

  if has_old_record:
    old_is_product = (old.src is not None)
    if is_product != old_is_product: # nature of the target changed.
      note(target, f"target is {'now' if is_product else 'no longer'} a product.")
      is_changed = True
    if not has_old_file:
      note(target, 'old product was deleted.')

  if is_product:
    if has_old_file and has_old_record:
      check_product_not_modified(ctx, target, actual_path, size=size, mtime=mtime, old=old)
    return update_product(ctx, target, actual_path, is_changed=is_changed, size=size, mtime=mtime, old=old)
  else:
    return update_non_product(ctx, target, is_changed=is_changed, size=size, mtime=mtime, old=old)


def check_product_not_modified(ctx: Ctx, target: str, actual_path: str, size: int, mtime: float, old: TargetRecord) -> None:
  # existing product should not have been modified since record was stored.
  # if the size changed then it was definitely modified.
  # otherwise, if the mtime is unchanged, assume that the file is ok, for speed.
  # if the mtime changed, check the hash;
  # the user might have made an accidental edit and then reverted it,
  # and we would rather compute the hash than report a false problem.
  if size != old.size or (mtime != old.mtime and
    (size > max_hash_size or hash_for_path(actual_path, size, max_hash_size) != old.hash)):
    ctx.dbg(target, f'size: {old.size} -> {size}; mtime: {old.mtime} -> {mtime}')
    # TODO: change language depending on whether product is derived from a patch?
    raise error(target, 'existing product has changed; did you mean to update a patch?\n'
      f'  Otherwise, save your changes if necessary and then `muck clean {target}`.')


def update_product(ctx: Ctx, target: str, actual_path: str, is_changed: bool, size: int, mtime: float, old: TargetRecord) -> bool:
  ctx.dbg(target, 'update_product')
  src = source_for_target(ctx, target)
  validate_target_or_error(ctx, src)
  ctx.dbg(target, f'src: {src}')
  if old.src != src:
    is_changed = True
    if old.src:
      note(target, f'source path of target product changed\n  was: {old.src}\n  now: {src}')
  is_changed |= update_dependency(ctx, src, dependent=target)

  for sub_dep in expanded_wild_deps(ctx, target, src):
    is_changed |= update_dependency(ctx, sub_dep, dependent=target)

  if is_changed: # must rebuild product.
    tmp_paths = build_product(ctx, target, src, actual_path)
    ctx.dbg(target, f'tmp_paths: {tmp_paths}')
    if tmp_paths:
      is_changed = False # now determine if any product has actually changed.
      for tmp_path in tmp_paths:
        is_changed |= update_product_with_tmp(ctx, src=src, tmp_path=tmp_path)
      return is_changed
    else: # no tmp paths; this is a weird corner case that we always treat as changed.
      return update_deps_and_record(ctx, target=target, actual_path=actual_path,
        is_changed=True, size=0, mtime=0, file_hash=None, src=src, old=old)
  else: # not is_changed.
    return update_deps_and_record(ctx, target=target, actual_path=actual_path,
      is_changed=is_changed, size=size, mtime=mtime, file_hash=old.hash, src=src, old=old)


def expanded_wild_deps(ctx: Ctx, target: str, src: str) -> Iterable[str]:
  wild_deps = ctx.db.get_record(src).wild_deps
  if not wild_deps: return
  m = match_wilds(path_stem(src), target)
  bindings = m.groupdict()
  for wild_dep in wild_deps:
    b = bindings.copy()
    for name, _, _, value_type in parse_formatters(wild_dep):
      b[name] = value_type(bindings[name])
    yield wild_dep.format(**b)


def update_product_with_tmp(ctx: Ctx, src: str, tmp_path: str) -> bool:
  product_path, ext = split_stem_ext(tmp_path)
  if ext not in (out_ext, tmp_ext):
    raise error(tmp_path, f'product output path has unexpected extension: {ext!r}')
  if not is_product_path(ctx, product_path):
     raise error(product_path, 'product path is not in build dir.')
  target = product_path[len(ctx.build_dir_slash):]
  size, mtime, old = calc_size_mtime_old(ctx, target, tmp_path)
  file_hash = hash_for_path(tmp_path, size, max_hash_size)
  is_changed = (size != old.size or size > max_hash_size or file_hash != old.hash)
  if is_changed:
    ctx.db.delete_record(target=target) # delete metadata if it exists, just before overwrite, in case muck fails before update.
  move_file(tmp_path, product_path, overwrite=True) # move regardless; if not changed, just cleans up the identical tmp file.
  note(target, f"product {'changed' if is_changed else 'did not change'}; {format_byte_count(size)}.")
  return update_deps_and_record(ctx, target=target, actual_path=product_path,
    is_changed=is_changed, size=size, mtime=mtime, file_hash=file_hash, src=src, old=old)


def update_non_product(ctx: Ctx, target: str, is_changed: bool, size, mtime, old) -> bool:
  ctx.dbg(target, 'update_non_product')
  file_hash = hash_for_path(target, size, max_hash_size) # must be calculated in all cases.
  if is_changed:
    product = product_path_for_target(ctx, target)
    remove_file_if_exists(product)
    make_link(target, product, make_dirs=True)
  else: # all we know so far is that it exists and status as a source has not changed.
    is_changed = (size != old.size or file_hash != old.hash)
    if is_changed: # this is more interesting; report.
      note(target, 'source changed.')

  return update_deps_and_record(ctx, target, target,
    is_changed=is_changed, size=size, mtime=mtime, file_hash=file_hash, src=None, old=old)


def update_deps_and_record(ctx, target: str, actual_path: str,
  is_changed: bool, size: int, mtime: float, file_hash: Optional[bytes], src: Optional[str], old: TargetRecord) -> bool:
  ctx.dbg(target, 'update_deps_and_record')
  if is_changed:
    deps, wild_deps = calc_dependencies(actual_path, ctx.dir_names)
    for dep in deps:
      try: validate_target(ctx, dep)
      except InvalidTarget as e:
        exit(f'muck error: {target}: invalid dependency: {e.target!r}: {e.msg}')
      # TODO: validate wild_deps? how?
  else:
    deps = old.deps
    wild_deps = old.wild_deps
  for dep in deps:
    is_changed |= update_dependency(ctx, dep, dependent=target)

  assert ctx.statuses.get(target) is None
  #^ use get (which defaults to None) because when a script generates multiple outputs,
  # this function gets called without a preceding call to update_dependency.
  # TODO: is there a case where two different scripts could generate the same named file,
  # causing this assertion to fail?
  ctx.statuses[target] = is_changed # replace sentinal with final value.
  if is_changed:
    record = TargetRecord(path=target, size=size, mtime=mtime, hash=file_hash, src=src, deps=deps, wild_deps=wild_deps)
    ctx.dbg(target, f'updated record:\n  {record}')
    if is_empty_record(old):
      ctx.db.insert_record(record)
    else:
      ctx.db.update_record(record)

  return is_changed


# Dependency calculation.

def calc_dependencies(path: str, dir_names: Dict[str, Tuple[str, ...]]) -> Tuple[List[str], List[str]]:
  '''
  Infer the dependencies for the file at `path`.
  '''
  ext = path_ext(path)
  try:
    dep_fn = dependency_fns[ext]
  except KeyError:
    return ([], [])
  with open(path) as f:
    all_deps = dep_fn(path, f, dir_names)
    return fan_by_pred(sorted(set(all_deps)), has_formatter)


def list_dependencies(src_path: str, src_file: TextIO, dir_names: Dict[str, Tuple[str, ...]]) -> List[str]:
  'Calculate dependencies for .list files.'
  lines = (line.strip() for line in src_file)
  return [l for l in lines if l and not l.startswith('#')]


def mush_dependencies(src_path: str, src_file: TextIO, dir_names: Dict[str, Tuple[str, ...]]) -> Iterable[str]:
  'Calculate dependencies for .mush files.'
  for line in src_file:
    for token in shlex.split(line):
      if path_ext(token):
        yield token


try: from pat import pat_dependencies
except ImportError:
  def pat_dependencies(src_path, src_file, dir_names):
    raise error(src_path, '`pat` is not installed; run `pip install pat-tool`.')


try: from writeup.v0 import writeup_dependencies
except ImportError:
  def writeup_dependencies(src_path, src_file, dir_names):
    raise error(src_path, '`writeup` is not installed; run `pip install writeup-tool`.')


dependency_fns = {
  '.list' : list_dependencies,
  '.mush' : mush_dependencies,
  '.pat' : pat_dependencies,
  '.py' : py_dependencies,
  '.wu' : writeup_dependencies,
}


# Build.


def build_product(ctx: Ctx, target: str, src_path: str, prod_path: str) -> List[str]:
  '''
  Run a source file, producing zero or more products.
  Return a list of produced product paths.
  '''
  src_ext = path_ext(src_path)
  try:
    build_tool = build_tools[src_ext]
  except KeyError:
    # TODO: fall back to generic .deps file.
    raise error(target, f'unsupported source file extension: {src_ext!r}')
  prod_path_out = prod_path + out_ext
  prod_path_tmp = prod_path + tmp_ext
  remove_file_if_exists(prod_path_out)
  remove_file_if_exists(prod_path_tmp)

  if not build_tool:
    note(target, 'no op.')
    return False # no product.

  prod_dir = path_dir(prod_path)
  make_dirs(prod_dir)

  # Extract args from the combination of wilds in the source and the matching target.
  m = match_wilds(target_path_for_source(ctx, src_path), target)
  if m is None:
    raise error(target, f'internal error: match failed; src_path: {src_path!r}')
  argv = [src_path] + list(m.groups())
  cmd = build_tool + argv

  try: env_fn = build_tool_env_fns[src_ext]
  except KeyError: env = None
  else:
    env = os.environ.copy()
    custom_env = env_fn()
    env.update(custom_env)

  note(target, f"building: `{' '.join(shlex.quote(w) for w in cmd)}`")
  out_file = open(prod_path_out, 'wb')
  time_start = time.time()
  code = runC(cmd, cwd=ctx.build_dir, env=env, out=out_file)
  time_elapsed = time.time() - time_start
  out_file.close()
  if code != 0:
    raise error(target, f'build failed with code: {code}')

  def cleanup_out() -> None:
    if file_size(prod_path_out) == 0:
      remove_file(prod_path_out)
    else:
      warn(target, f'wrote data directly to `{prod_path_tmp}`;\n  ignoring output captured in `{prod_path_out}`')

  manif_path = ctx.build_dir_slash + manifest_path(argv)
  try: f = open(manif_path)
  except FileNotFoundError: # no manifest.
    if path_exists(prod_path_tmp):
      via = 'tmp'
      tmp_paths = [prod_path_tmp]
      cleanup_out()
    else: # no tmp; use captured stdout.
      via = 'stdout'
      tmp_paths = [prod_path_out]
  else: # found manifest.
    via = 'manifest'
    tmp_paths = list(product_path_for_target(ctx, line.rstrip('\n')) for line in f)
    cleanup_out()
    if prod_path_tmp not in tmp_paths:
      errL('prod_path_tmp: ', prod_path_tmp)
      errSL(*tmp_paths)
      raise error(target, f'product does not appear in manifest ({len(tmp_paths)} records): {manif_path}')
    remove_file(manif_path)
  time_msg = f'{time_elapsed:0.2f} seconds ' if ctx.report_times else ''
  note(target, f'finished: {time_msg}(via {via}).')
  return tmp_paths


_pythonV_V = 'python' + '.'.join(str(v) for v in sys.version_info[:2])
build_tools: Dict[str, List[str]] = {
  '.list' : [], # no-op.
  '.mush' : ['mush'],
  '.pat' : ['pat', 'apply'],
  '.py' : [_pythonV_V],
    # use the same version of python that muck is running under.
  '.wu' : ['writeup'],
}


def py_env() -> Dict[str, str]:
  return { 'PYTHONPATH' : current_dir() }

build_tool_env_fns = {
  '.py' : py_env
}


# Targets and paths.


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
    raise InvalidTarget(target, f'cannot contain {inv_m.group(0)!r}.')
  if target[0] == '.' or target[-1] == '.':
    raise InvalidTarget(target, "cannot begin or end with '.'.")
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


def validate_target_or_error(ctx: Ctx, target: str) -> None:
  try: validate_target(ctx, target)
  except InvalidTarget as e:
    exit(f'muck error: invalid target: {e.target!r}; {e.msg}')


def is_product_path(ctx: Ctx, path: str) -> bool:
  return path.startswith(ctx.build_dir_slash)


def product_path_for_target(ctx: Ctx, target_path: str) -> str:
  if target_path == ctx.build_dir or is_product_path(ctx, target_path):
    raise ValueError(f'provided target path is prefixed with build dir: {target_path}')
  return path_join(ctx.build_dir, target_path)


def target_path_for_source(ctx: Ctx, source_path: str) -> str:
  'Return the target path for `source_path` (which may itself be a product).'
  path = path_stem(source_path) # strip off source ext.
  if is_product_path(ctx, path): # source might be a product.
    return path[len(ctx.build_dir_slash):]
  else:
    return path


_wildcard_re = re.compile(r'(%+)')

def match_wilds(wildcard_path: str, string: str) -> Optional[Match[str]]:
  '''
  Match a string against a wildcard/format path.
  '''
  r = format_to_re(wildcard_path)
  return r.fullmatch(string)


# Utilities.


def hash_for_path(path: str, size: int, max_hash_size: int) -> bytes:
  '''
  Return a hash string for the contents of the file at `path`, up to `max_hash_size`.
  For files larger than `max_hash_size`, hash the first and last `max_hash_size//2` bytes;
  thus this hash value does not guarantee that changes will be detected,
  but does a decent job of detecting changes by checking the start and end of the file.
  '''
  hash_chunk_size = 1 << 16
  #^ a quick timing experiment suggested that chunk sizes larger than this are not faster.
  assert max_hash_size % hash_chunk_size == 0
  max_chunks = max_hash_size // hash_chunk_size
  try: f = open(path, 'rb')
  except IsADirectoryError: raise error(path, 'expected a file but found a directory')
  h = sha256()
  if size <= max_hash_size:
    for i in range(max_chunks):
      chunk = f.read(hash_chunk_size)
      if not chunk: break
      h.update(chunk)
  else: # too large; read half from start, half from the end.
    half_chunks = max_chunks // 2
    for i in range(half_chunks):
      h.update(f.read(hash_chunk_size))
    f.seek(max_hash_size//2, 2) # note: whence=2 seeks backwards from end.
    #^ TODO: if whence=2 is unsupported, just absorb that exception and read the second half from current pos.
    for i in range(half_chunks):
      h.update(f.read(hash_chunk_size))
  return h.digest()


def hash_string(hash: bytes) -> str:
  return base64.urlsafe_b64encode(hash).decode()


def calc_size_mtime_old(ctx: Ctx, target: str, actual_path: str) -> tuple:
  try:
    size, mtime = file_size_and_mtime(actual_path)
  except FileNotFoundError:
    size, mtime = 0, 0
  ctx.dbg(target, f'size: {size}; mtime: {mtime}')
  return size, mtime, ctx.db.get_record(target=target)


def file_size_and_mtime(path: str) -> Tuple[int, float]:
  stats = os.stat(path)
  return (stats.st_size, stats.st_mtime)


def source_for_target(ctx: Ctx, target: str) -> str:
  '''
  Find the unique source path whose name matches `target`, or else error.
  '''
  src_dir, prod_name = split_dir_name(target)
  src_name = source_candidate(ctx, target, src_dir, prod_name)
  src = path_join(src_dir, src_name)
  assert src != target
  return src


def source_candidate(ctx: Ctx, target: str, src_dir: str, prod_name: str) -> str:
  src_dir = src_dir or '.'
  try: src_dir_names = list_dir_filtered(ctx, src_dir)
  except FileNotFoundError: raise error(target, f'no such source directory: `{src_dir}`')
  candidates = list(filter_source_names(src_dir_names, prod_name))
  if len(candidates) == 1:
    return candidates[0]
  # error.
  deps = ', '.join(sorted(ctx.dependents[target])) or target
  if len(candidates) == 0:
    raise error(deps, f'no source candidates matching `{target}` in `{src_dir}`')
  else:
    raise error(deps, f'multiple source candidates matching `{target}`: {candidates}')


def list_dir_filtered(ctx: Ctx, src_dir: str) -> List[str]:
  '''
  Given src_dir, cache and return the list of names that might be source files.
  TODO: eventually this should be replaced by using os.scandir.
  '''
  try: return ctx.dir_names[src_dir]
  except KeyError: pass
  names = [n for n in list_dir(src_dir, hidden=False)
    if n not in ctx.reserved_names and path_ext(n) not in reserved_or_ignored_exts]
  ctx.dir_names[dir] = names
  return names


def filter_source_names(names: Iterable[str], prod_name: str) -> Iterable[str]:
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


def note(path: str, *items: Any) -> None:
  errL(f'muck note: {path}: ', *items)

def warn(path: str, *items: Any) -> None:
  errL(f'muck WARNING: {path}: ', *items)

def error(path: str, *items: Any) -> SystemExit:
  return SystemExit(''.join((f'muck error: {path}: ',) + items))
