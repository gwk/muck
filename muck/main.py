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
import re
import time

from argparse import ArgumentParser
from collections import defaultdict, namedtuple
from datetime import datetime
from hashlib import sha256
from typing import *
from typing import BinaryIO, IO, Match, TextIO

from .pithy.ansi import TXT_L_ERR, TXT_Y_ERR, RST_ERR
from .pithy.format import format_to_re
from .pithy.fs import *
from .pithy.io import *
from .pithy.iterable import fan_by_pred
from .pithy.json_utils import load_json, write_json
from .pithy.pipe import DuplexPipe
from .pithy.string_utils import format_byte_count
from .pithy.task import launch, runC

from .ctx import Ctx, InvalidTarget, validate_target
from .db import TargetRecord, DB, DBError
from .constants import *
from .paths import manifest_path
from .py_deps import py_dependencies
from .server import serve_build


def main() -> None:
  arg_parser = ArgumentParser(description=__doc__)
  arg_parser.add_argument('targets', nargs='*', default=[], help="target file names; defaults to 'index.html'.")
  arg_parser.add_argument('-no-times', action='store_true', help='do not report process times.')
  arg_parser.add_argument('-dbg', action='store_true', help='log lots of details to stderr.')
  arg_parser.add_argument('-force', action='store_true', help='rebuild specified targets even if they are up to date.')
  arg_parser.add_argument('-build-dir', default='_build', help="specify build directory; defaults to '_build'.")
  arg_parser.add_argument('-serve', nargs='?', const='index.html',
    help='serve contents of build directory via local HTTP, and open the specified target in the browser.')

  group = arg_parser.add_argument_group('special commands')

  # map command names to (fn, wants_dflt_target).
  command_fns: Dict[str, Tuple[Callable[[Ctx, List[str]], None], bool]] = {
    None : (muck_build, True), # default command.
  }

  def add_cmd(cmd: str, fn: Callable[[Ctx, List[str]], None], wants_dflt: bool, help: str) -> None:
    group.add_argument('-' + cmd, dest='cmds', action='append_const', const=cmd, help=help)
    command_fns[cmd] = (fn, wants_dflt)

  add_cmd('clean',        muck_clean,         True, help='clean the specified targets or the entire build folder.')
  add_cmd('deps',         muck_deps,          True, help='print targets and their dependencies as a visual hierarchy.')
  add_cmd('deps-list',    muck_deps_list,     True, help='print targets and their dependencies as a list.')
  add_cmd('prod-list',    muck_prod_list,     True, help='print products as a list.')
  add_cmd('create-patch', muck_create_patch,  False, help='create a patch; usage: [original] [modified.pat]')
  add_cmd('update-patch', muck_update_patch,  False, help='update a patch: usage: [target.pat]')

  args = arg_parser.parse_args()
  cmds = args.cmds or [None]
  build_dir = args.build_dir.rstrip('/')
  build_dir_slash = build_dir + '/'
  db_name = '_muck'
  db_path = build_dir_slash + db_name

  reserved_names = frozenset({
    'muck',
    build_dir,
    db_name,
  })

  if args.dbg:
    def dbg(path: str, *items: str) -> None:
      errL('muck dbg: ', path, ': ', *items)
  else:
    def dbg(path: str, *items: str) -> None: pass

  if len(cmds) > 1:
    desc = ', '.join(repr('-' + c) for c in cmds)
    exit(f'muck error: multiple commands specified: {desc}.')

  cmd = cmds[0]

  make_dirs(build_dir) # required to create new DB.

  if cmd == 'clean' and not args.targets:
    # special case: we do not want to initialize the DB.
    muck_clean_all(build_dir)
    exit()

  ctx = Ctx(args=args, db=DB(path=db_path), build_dir=build_dir, build_dir_slash=build_dir_slash,
    reserved_names=reserved_names, report_times=(not args.no_times), dbg=dbg)

  # `-serve` option captures the following target if it is present; add that to the target list.
  targets = args.targets + ([args.serve] if args.serve else [])

  cmd_fn, wants_dflt_target = command_fns[cmd]
  if wants_dflt_target and not targets: targets = ['index.html']

  for t in targets: validate_target_or_error(ctx, t)

  cmd_fn(ctx, targets)


# Commands.


def muck_build(ctx: Ctx, targets: List[str]) -> None:
  'muck default command: update each specified target.'

  def update_target(target): # closure to pass to serve_build.
    update_dependency(ctx, target, dependent=None, force=ctx.args.force)

  for target in targets:
    if path_exists(target):
      stem, ext = split_stem_ext(target)
      if ext in dependency_fns:
        note(target, f'specified target is a source and not a product; building {stem!r}...')
        target = stem
      else:
        note(target, 'specified target is a source and not a product.')
    update_target(target)
  if ctx.args.serve:
    serve_build(ctx, main_target=ctx.args.serve, update_target=update_target)


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
    prod_path = ctx.product_path_for_target(target)
    remove_file_if_exists(prod_path)
    ctx.db.delete_record(target=target)


def muck_deps(ctx: Ctx, targets: List[str]) -> None:
  '`muck -deps [targets...]` command.'
  for target in sorted(targets):
    update_dependency(ctx, target, dependent=None)

  roots = set(targets)
  roots.update(t for t, s in ctx.dependents.items() if len(s) > 1)

  def visit(depth: int, target: str) -> None:
    record = ctx.db.get_record(target)
    assert record is not None
    dependents = ctx.dependents[target]
    src = record.src
    deps = record.deps
    dyn_deps = record.dyn_deps
    some = bool(src) or bool(deps) or bool(dyn_deps)
    if depth == 0 and len(dependents) > 0:
      suffix = f' (dependents: {" ".join(sorted(dependents))}):'
    elif len(dependents) > 1: suffix = '*'
    elif some: suffix = ':'
    else: suffix = ''
    outL('  ' * depth, target, suffix)
    if depth > 0 and len(dependents) > 1: return
    if src is not None:
      visit(depth + 1, src)
    for dep in deps:
      visit(depth + 1, dep)
    for dyn_dep in dyn_deps:
      visit(depth + 1, dyn_dep)

  for root in sorted(roots):
    outL()
    visit(0, root)


def muck_deps_list(ctx: Ctx, targets: List[str]) -> None:
  '`muck -deps-list [targets...]` command.'
  for target in targets:
    update_dependency(ctx, target, dependent=None)
  outLL(*sorted(ctx.change_times))


def muck_prod_list(ctx: Ctx, targets: List[str]) -> None:
  '`muck -prod-list [targets...]` command.'
  for target in targets:
    update_dependency(ctx, target, dependent=None)
  outLL(*sorted(ctx.product_path_for_target(t) for t in ctx.change_times))


def muck_create_patch(ctx: Ctx, args: List[str]) -> None:
  '`muck -create-patch` command.'
  if len(args) != 2:
    exit('''\
muck -create-patch error: requires two arguments: [original] [modified].
This command creates an empty patch called [modified].pat, and copies [original] to _build/[modified].''')
  original, modified = args
  patch = modified + '.pat'
  if original.endswith('.pat'):
    exit(f"muck -create-patch error: 'original' should not be a patch file: {original}")
  if modified.endswith('.pat'):
    exit(f"muck -create-patch error: 'modified' should not be a patch file: {modified}")
  if path_exists(modified) or ctx.db.contains_record(patch):
    exit(f"muck -create-patch error: 'modified' is an existing target: {modified}")
  if path_exists(patch) or ctx.db.contains_record(patch):
    exit(f"muck -create-patch error: patch is an existing target: {patch}")
  update_dependency(ctx, original, dependent=None)
  cmd = ['pat', 'create', original, modified, '../' + patch]
  cmd_str = ' '.join(shlex.quote(w) for w in cmd)
  errL(f'muck -create-patch note: creating patch: `{cmd_str}`')
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


# Default update functionality.


def update_dependency(ctx: Ctx, target: str, dependent: Optional[str], force=False) -> int:
  'returns transitive change_time.'
  validate_target(ctx, target)

  if dependent is not None:
    ctx.dependents[target].add(dependent)

  try: change_time = ctx.change_times[target]
  except KeyError: pass
  else: # if in ctx.change_times, this path has already been visited during this build process run.
    if change_time is None: # recursion sentinal.
      involved_paths = sorted(path for path, t in ctx.change_times.items() if t is None)
      raise error(target, 'target has circular dependency; involved paths:', *('\n  ' + p for p in involved_paths))
    return change_time

  ctx.change_times[target] = None # recursion sentinal is replaced before return by update_deps_and_record.

  ctx.dbg(target, f'examining... (dependent={dependent})')
  is_product = not path_exists(target)
  if is_product and is_link(target):
    raise error(target, f'target is a dangling symlink to: {read_link(target)}')
  actual_path = ctx.product_path_for_target(target) if is_product else target

  old = ctx.db.get_record(target=target)
  needs_update = force or (old is None)

  if old is not None:
    old_is_product = (old.src is not None)
    if is_product != old_is_product: # nature of the target changed.
      note(target, f"target is {'now' if is_product else 'no longer'} a product.")
      needs_update = True

  if is_product:
    size: Optional[int] = None
    mtime = 0.0
    try: size, mtime = file_size_and_mtime(actual_path)
    except FileNotFoundError: pass
    if old is not None:
      if size is None:
        note(target, 'old product was deleted.')
        is_changed = True
      else:
        check_product_not_modified(ctx, target, actual_path, size=size, mtime=mtime, old=old)
    return update_product(ctx, target, actual_path, needs_update=needs_update, size=size, mtime=mtime, old=old)
  else:
    return update_non_product(ctx, target, needs_update=needs_update, old=old)


def check_product_not_modified(ctx: Ctx, target: str, actual_path: str, size: int, mtime: float, old: TargetRecord) -> None:
  # existing product should not have been modified since record was stored.
  # if the size changed then it was definitely modified.
  # otherwise, if the mtime is unchanged, assume that the contents are unchanged, for speed.
  if size == old.size and mtime == old.mtime: return
  # if mtime is changed but contents are not, the user might have made an accidental edit and then reverted it.
  if size == old.size and hash_for_path(actual_path) == old.hash:
    note(target, f'product mtime changed but contents did not: {disp_mtime(old.mtime)} -> {disp_mtime(mtime)}.')
    # TODO: revert mtime?
    return
  # TODO: change language depending on whether product is derived from a patch?
  raise error(target, 'existing product has changed; did you mean to update a patch?\n'
    f'  Otherwise, save your changes if necessary and then `muck clean {target}`.')


def update_product(ctx: Ctx, target: str, actual_path: str, needs_update: bool, size: Optional[int], mtime: float,
 old: Optional[TargetRecord]) -> int:
  'returns transitive change_time.'
  ctx.dbg(target, 'update_product')
  src = source_for_target(ctx, target)
  validate_target_or_error(ctx, src)
  ctx.dbg(target, f'src: ', src)
  if old is not None and old.src != src:
    needs_update = True
    note(target, f'source path of target product changed\n  was: {old.src}\n  now: {src}')

  last_update_time = 0 if old is None else old.update_time
  src_change_time = update_dependency(ctx, src, dependent=target)
  needs_update = needs_update or last_update_time < src_change_time
  update_time = max(last_update_time, src_change_time)

  if not needs_update: # src has not changed since update.
    # check if any of the previously recorded dynamic dependencies have changed;
    # if they have not, then no rebuild is necessary.
    assert old is not None
    for dyn_dep in old.dyn_deps:
      dep_change_time = update_dependency(ctx, dyn_dep, dependent=target)
      update_time = max(update_time, dep_change_time)
  needs_update = needs_update or last_update_time < update_time

  if needs_update: # must rebuild product.
    dyn_change_time, dyn_deps, tmp_paths = build_product(ctx, target, src, actual_path)
    update_time = max(update_time, dyn_change_time)
    ctx.dbg(target, f'tmp_paths: {tmp_paths}')
    assert tmp_paths
    for tmp_path in tmp_paths:
      a_target, a_change_time = update_product_with_tmp(ctx, src=src, dyn_deps=dyn_deps, tmp_path=tmp_path, update_time=update_time)
      if a_target == target:
        change_time = a_change_time
    assert change_time > 0
    return change_time
  else: # not needs_update.
    assert size is not None
    assert old is not None
    return update_deps_and_record(ctx, target=target, actual_path=actual_path, is_changed=False, size=size, mtime=mtime,
      change_time=old.change_time, update_time=update_time, file_hash=old.hash, src=src, dyn_deps=old.dyn_deps, old=old)


def update_product_with_tmp(ctx: Ctx, src: str, dyn_deps: Tuple[str, ...], tmp_path: str, update_time: int) -> Tuple[str, int]:
  'Returns (target, change_time).'
  product_path, ext = split_stem_ext(tmp_path)
  if ext not in (out_ext, tmp_ext):
    raise error(tmp_path, f'product output path has unexpected extension: {ext!r}')
  if not ctx.is_product_path(product_path):
     raise error(product_path, 'product path is not in build dir.')
  target = product_path[len(ctx.build_dir_slash):]
  old = ctx.db.get_record(target=target)
  size, mtime = file_size_and_mtime(tmp_path)
  file_hash = hash_for_path(tmp_path)
  is_changed = (old is None or size != old.size or file_hash != old.hash)
  if is_changed:
    change_time = update_time
    change_verb = 'is new' if old is None else 'changed'
    ctx.db.delete_record(target=target) # delete metadata if it exists, just before overwrite, in case muck fails before update.
    move_file(tmp_path, product_path, overwrite=True)
  else:
    assert old is not None
    change_time = old.change_time
    change_verb = 'did not change'
    mtime = old.mtime # we are abandoning the new file.
    remove_file(tmp_path) # do not overwrite old because we want to preserve the old mtime.
  note(target, f"product {change_verb}; {format_byte_count(size)}.")
  return target, update_deps_and_record(ctx, target=target, actual_path=product_path, is_changed=is_changed, size=size, mtime=mtime,
    change_time=change_time, update_time=update_time, file_hash=file_hash, src=src, dyn_deps=dyn_deps, old=old)


def update_non_product(ctx: Ctx, target: str, needs_update: bool, old: Optional[TargetRecord]) -> int:
  'returns transitive change_time.'
  ctx.dbg(target, 'update_non_product')
  size, mtime = file_size_and_mtime(target)
  product_link = ctx.product_path_for_target(target) # non_products get linked into build dir.

  if needs_update:
    remove_file_if_exists(product_link)
    make_link(target, product_link, make_dirs=True)
  elif not is_link(product_link):
    if not path_exists(product_link): # link was deleted? replace it.
      make_link(target, product_link, make_dirs=True)
    else:
      error(target, 'non-product link in build directory appears to have been replaced with a different file.')

  if needs_update:
    is_changed = True
    file_hash = hash_for_path(target)
  else: # all we know so far is that it exists and status as a non-product has not changed.
    appears_changed = (old is None or size != old.size or mtime != old.mtime)
    if appears_changed: # check if contents actually changed.
      file_hash = hash_for_path(target)
      is_changed = (old.hash != file_hash)
    else: # assume not changed based on size/mtime; otherwise we constantly recalculate hashes for large sources.
      is_changed = False
      file_hash = old.hash

  if is_changed:
    if not needs_update: note(target, 'source changed.') # only want to report this on subsequent changes.
    change_time = ctx.db.inc_ptime()
  else:
    assert old is not None
    change_time = old.change_time
    file_hash = old.hash
    if mtime != old.mtime:
      note(target, f'source modification time changed but contents did not.')
  return update_deps_and_record(ctx, target, actual_path=target, is_changed=is_changed,
    size=size, mtime=mtime, change_time=change_time, update_time=change_time, file_hash=file_hash, src=None, dyn_deps=(), old=old)
  # TODO: non_product update_time is meaningless? mark as -1?


def update_deps_and_record(ctx, target: str, actual_path: str, is_changed: bool, size: int, mtime: float,
 change_time: int, update_time: int, file_hash: bytes, src: Optional[str], dyn_deps: Tuple[str, ...], old: Optional[TargetRecord]) -> int:
  'returns transitive change_time.'
  ctx.dbg(target, 'update_deps_and_record')
  if is_changed:
    deps = calc_dependencies(actual_path, ctx.dir_names)
    for dep in deps:
      try: validate_target(ctx, dep)
      except InvalidTarget as e:
        exit(f'muck error: {target}: invalid dependency: {e.target!r}: {e.msg}')
  else:
    assert old is not None
    deps = old.deps
  for dep in deps:
    dep_change_time = update_dependency(ctx, dep, dependent=target)
    change_time = max(change_time, dep_change_time)
  update_time = max(update_time, change_time)

  assert ctx.change_times.get(target) is None
  #^ use get (which defaults to None) because when a script generates multiple outputs,
  # this function gets called without a preceding call to update_dependency.
  # note: it is possible that two different scripts could generate the same named file, causing this assertion to fail.
  # TODO: change this from an assertion to an informative error.
  ctx.change_times[target] = change_time # replace sentinal with final value.
  # always update record, because even if is_changed=False, mtime may have changed.
  record = TargetRecord(path=target, size=size, mtime=mtime, change_time=change_time, update_time=update_time,
    hash=file_hash, src=src, deps=deps, dyn_deps=dyn_deps)
  ctx.dbg(target, f'updated record:\n  ', record)
  ctx.db.insert_or_replace_record(record)
  return change_time


# Dependency calculation.

def calc_dependencies(path: str, dir_names: Dict[str, Tuple[str, ...]]) -> Tuple[str, ...]:
  '''
  Infer the dependencies for the file at `path`.
  '''
  ext = path_ext(path)
  try:
    dep_fn = dependency_fns[ext]
  except KeyError:
    return ()
  with open(path) as f:
    return tuple(dep_fn(path, f, dir_names))


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


try: from pat import pat_dependencies # type: ignore
except ImportError:
  def pat_dependencies(src_path: str, src_file: TextIO, dir_names: Dict[str, Tuple[str, ...]]) -> List[str]:
    raise error(src_path, '`pat` is not installed; run `pip install pat-tool`.')


try: from writeup.v0 import writeup_dependencies # type: ignore
except ImportError:
  def writeup_dependencies(src_path: str, src_file: TextIO, dir_names: Dict[str, Tuple[str, ...]]) -> List[str]:
    raise error(src_path, '`writeup` is not installed; run `pip install writeup-tool`.')


dependency_fns: Dict[str, Callable[..., Iterable[str]]] = {
  '.list' : list_dependencies,
  '.mush' : mush_dependencies,
  '.pat' : pat_dependencies,
  '.py' : py_dependencies,
  '.wu' : writeup_dependencies,
}


# Build.


def build_product(ctx: Ctx, target: str, src_path: str, prod_path: str) -> Tuple[int, Tuple[str, ...], List[str]]:
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
    return 0, (), [] # no product.

  prod_dir = path_dir(prod_path)
  make_dirs(prod_dir)

  # Extract args from the combination of wilds in the source and the matching target.
  m = match_wilds(target_path_for_source(ctx, src_path), target)
  if m is None:
    raise error(target, f'internal error: match failed; src_path: {src_path!r}')
  argv = [src_path] + list(m.groups())
  cmd = build_tool + argv

  env = os.environ.copy()
  try:
    env_fn: Callable[[], Dict[str, str]] = build_tool_env_fns[src_ext]
  except KeyError: pass
  else:
    env.update(env_fn())

  note(target, f"building: `{' '.join(shlex.quote(w) for w in cmd)}`")
  dyn_time = 0
  dyn_deps: List[str] = []
  with cast(BinaryIO, open(prod_path_out, 'wb')) as out_file, DuplexPipe() as pipe:
    deps_recv, deps_send = pipe.left_files()
    env.update(zip(('DEPS_RECV', 'DEPS_SEND'), [str(fd) for fd in pipe.right_fds]))
    assert env['DEPS_RECV'] is not None
    assert env['DEPS_SEND'] is not None
    time_start = time.time()
    proc, _ = launch(cmd, cwd=ctx.build_dir, env=env, out=out_file, files=pipe.right_fds)
    pipe.close_right()
    while True:
      dep_line = deps_recv.readline()
      if not dep_line: break
      dep = dep_line.rstrip('\n')
      ctx.dbg(target, 'dep: ', dep)
      dyn_deps.append(dep)
      try:
        dep_time = update_dependency(ctx, dep, dependent=target) # ignore return value.
        dyn_time = max(dyn_time, dep_time)
      except (Exception, SystemExit):
        proc.kill() # this avoids a confusing exception message from the script when muck fails.
        raise
      print(dep, file=deps_send, flush=True)
    code = proc.wait()
    time_elapsed = time.time() - time_start

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
    tmp_paths = list(ctx.product_path_for_target(line.rstrip('\n')) for line in f)
    cleanup_out()
    if prod_path_tmp not in tmp_paths:
      errL('prod_path_tmp: ', prod_path_tmp)
      errSL(*tmp_paths)
      raise error(target, f'product does not appear in manifest ({len(tmp_paths)} records): {manif_path}')
    remove_file(manif_path)
  time_msg = f'{time_elapsed:0.2f} seconds ' if ctx.report_times else ''
  note(target, f'finished: {time_msg}(via {via}).')
  return dyn_time, tuple(dyn_deps), tmp_paths


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


def validate_target_or_error(ctx: Ctx, target: str) -> None:
  try: validate_target(ctx, target)
  except InvalidTarget as e:
    exit(f'muck error: invalid target: {e.target!r}; {e.msg}')


def target_path_for_source(ctx: Ctx, source_path: str) -> str:
  'Return the target path for `source_path` (which may itself be a product).'
  path = path_stem(source_path) # strip off source ext.
  if ctx.is_product_path(path): # source might be a product.
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


def hash_for_path(path: str) -> bytes:
  '''
  Return a hash string for the contents of the file at `path`.
  '''
  hash_chunk_size = 1 << 16
  #^ a quick timing experiment suggested that chunk sizes larger than this are not faster.
  try: f = open(path, 'rb')
  except IsADirectoryError: raise error(path, 'expected a file but found a directory')
  h = sha256()
  while True:
    chunk = f.read(hash_chunk_size)
    if not chunk: break
    h.update(chunk)
  return h.digest()


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
  ctx.dir_names[src_dir] = names
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
  errL(TXT_L_ERR, f'muck note: {path}: ', *items, RST_ERR)

def warn(path: str, *items: Any) -> None:
  errL(TXT_Y_ERR, f'muck WARNING: {path}: ', *items, RST_ERR)

def error(path: str, *items: Any) -> SystemExit:
  return SystemExit(''.join((f'muck error: {path}: ',) + items))


def disp_mtime(mtime: Optional[float]) -> str:
  return str(datetime.fromtimestamp(mtime)) if mtime else '0'
