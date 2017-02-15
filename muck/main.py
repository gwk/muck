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
from typing import Optional

from .pithy.format import has_formatter
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


def main():
  arg_parser = ArgumentParser(description=__doc__)
  arg_parser.add_argument('targets', nargs='*', default=[], help="target file names; defaults to 'index.html'.")
  arg_parser.add_argument('-no-times', action='store_true', help='do not report process times.')
  arg_parser.add_argument('-dbg', action='store_true', help='log lots of details to stderr.')
  arg_parser.add_argument('-force', action='store_true', help='rebuild specified targets even if they are up to date.')

  group = arg_parser.add_argument_group('special commands')
  def add_cmd(cmd, help): group.add_argument('-' + cmd, dest='cmds', action='append_const', const=cmd, help=help)

  add_cmd('clean', help='clean the specified targets or the entire build folder.')
  add_cmd('deps',  help='print dependencies of targets.')
  add_cmd('patch', help='create a patch; usage: [original] [modified.pat]')
  add_cmd('update-patch', help='update a patch: usage: [target.pat]')

  args = arg_parser.parse_args()
  cmds = args.cmds or []

  if args.dbg:
    def dbg(path, *items):
      errL(f'muck dbg: {path}: ', *items)
  else:
    def dbg(path, *items): pass

  if len(cmds) > 1:
    desc = ', '.join(repr('-' + c) for c in cmds)
    exit(f'muck error: multiple commands specified: {desc}.')

  make_dirs(build_dir) # required to create new DB.

  cmd = cmds[0] if cmds else None
  if cmd == 'clean' and not args.targets:
    muck_clean_all()
    exit()

  for t in args.targets: validate_target_or_error(t)

  ctx = Ctx(db=DB(path=db_path), statuses={}, dir_names={}, dependents=defaultdict(set),
    report_times=(not args.no_times), dbg=dbg)

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



Ctx = namedtuple('Ctx', 'db statuses dir_names dependents report_times dbg')
# db: DB.
# statuses: dict (target_path: str => is_changed: bool|Ellipsis).
# dir_names: dict (dir_path: str => names: [str]).
# dependents: defaultdict(set) (target_path: str => depedents).
# report_times: bool.
# dbg: debug printing function.


# Commands.


def muck_clean_all():
  '`muck -clean` command with no arguments.'
  remove_dir_contents(build_dir)


def muck_clean(ctx, args):
  '`muck -clean [targets...]` command.'
  assert args
  for target in args:
    if not ctx.db.contains_record(target_path=target):
      errFL('muck clean note: {}: skipping unknown target.', target)
      continue
    prod_path = product_path_for_target(target)
    remove_file_if_exists(prod_path)
    ctx.db.delete_record(target_path=target)


def muck_deps(ctx, targets):
  '`muck -deps [targets...]` command: print dependency information.'
  if not targets: targets = ['index.html']

  for target in sorted(targets):
    update_dependency(ctx, target, dependent=None)

  roots = set(targets)
  roots.update(t for t, s in ctx.dependents.items() if len(s) > 1)

  def visit(depth, target):
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


def muck_create_patch(ctx, args):
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
  orig_path = actual_path_for_target(original)
  mod_path = product_path_for_target(modified)
  cmd = ['pat', 'create', orig_path, mod_path, patch]
  errFL('muck -patch note: creating patch: `{}`', ' '.join(shlex.quote(w) for w in cmd))
  exit(runC(cmd))


def muck_update_patch(ctx, args):
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
  orig_target_path = deps[0]
  update_dependency(ctx, orig_target_path, dependent=None)
  orig_path = actual_path_for_target(orig_target_path)
  target_path = path_stem(patch_path)
  prod_path = product_path_for_target(target_path)
  patch_path_tmp = patch_path + tmp_ext
  cmd = ['pat', 'diff', orig_path, prod_path, patch_path_tmp]
  errFL('muck -update-patch note: diffing: `{}`', ' '.join(shlex.quote(w) for w in cmd))
  code = runC(cmd)
  # need to remove or update the target record to avoid the 'did you mean to patch?' safeguard.
  # for now, just delete it to be safe; this makes the target look stale.
  # TODO: update target_path instead.
  ctx.db.delete_record(target_path=target_path) # no-op if does not exist.


command_fns = {
  'clean'         : muck_clean,
  'deps'          : muck_deps,
  'patch'         : muck_create_patch,
  'update-patch'  : muck_update_patch,
}


# Default update functionality.


def update_dependency(ctx: Ctx, target_path: str, dependent: Optional[str], force=False) -> bool:
  '''
  returns is_changed.
  '''
  validate_target(target_path)

  if dependent is not None:
    ctx.dependents[target_path].add(dependent)

  try: # if in ctx.statuses, this path has already been visited on this run.
    status = ctx.statuses[target_path]
    if status is Ellipsis: # recursion sentinal.
      involved_paths = sorted(path for path, status in ctx.statuses.items() if status is Ellipsis)
      error(target_path, 'target has circular dependency; involved paths:', *('\n  ' + p for p in involved_paths))
    return status
  except KeyError: pass

  ctx.statuses[target_path] = Ellipsis # recursion sentinal is replaced before return.

  ctx.dbg(target_path, f'examining... (dependent={dependent})')
  is_product = not path_exists(target_path)
  if is_product and is_link(target_path):
    error(target_path, f'target is a dangling symlink to: {read_link(target_path)}')
  actual_path = product_path_for_target(target_path) if is_product else target_path
  size, mtime, old = calc_size_mtime_old(ctx, target_path, actual_path)
  has_old_file = (mtime > 0)
  has_old_record = not is_empty_record(old)

  is_changed = force or (not has_old_file) or (not has_old_record)

  if has_old_record:
    old_is_product = (old.src is not None)
    if is_product != old_is_product: # nature of the target changed.
      note(target_path, f"target is {'now' if is_product else 'no longer'} a product.")
      is_changed = True
    if not has_old_file:
      note(target_path, 'old product was deleted.')

  if is_product:
    if has_old_file and has_old_record:
      check_product_not_modified(ctx, target_path, actual_path, size=size, mtime=mtime, old=old)
    return update_product(ctx, target_path, actual_path, is_changed=is_changed, size=size, mtime=mtime, old=old)
  else:
    return update_non_product(ctx, target_path, is_changed=is_changed, size=size, mtime=mtime, old=old)


def check_product_not_modified(ctx, target_path, actual_path, size, mtime, old):
  # existing product should not have been modified since record was stored.
  # if the size changed then it was definitely modified.
  # otherwise, if the mtime is unchanged, assume that the file is ok, for speed.
  # if the mtime changed, check the hash;
  # the user might have made an accidental edit and then reverted it,
  # and we would rather compute the hash than report a false problem.
  if size != old.size or (mtime != old.mtime and
    (size > max_hash_size or hash_for_path(actual_path, size, max_hash_size) != old.hash)):
    ctx.dbg(target_path, f'size: {old.size} -> {size}; mtime: {old.mtime} -> {mtime}')
    # TODO: change language depending on whether product is derived from a patch?
    error(target_path, 'existing product has changed; did you mean to update a patch?\n'
      f'  Otherwise, save your changes if necessary and then `muck clean {target_path}`.')


def update_product(ctx: Ctx, target_path: str, actual_path, is_changed, size, mtime, old) -> bool:
  ctx.dbg(target_path, 'update_product')
  src = source_for_target(ctx, target_path)
  validate_target_or_error(src)
  ctx.dbg(target_path, f'src: {src}')
  if old.src != src:
    is_changed = True
    if old.src:
      note(target_path, f'source path of target product changed\n  was: {old.src}\n  now: {src}')
  is_changed |= update_dependency(ctx, src, dependent=target_path)

  for sub_dep in expanded_wild_deps(ctx, target_path, src):
    is_changed |= update_dependency(ctx, sub_dep, dependent=target_path)

  if is_changed: # must rebuild product.
    actual_src = actual_path_for_target(src) # source might itself be a product.
    tmp_paths = build_product(ctx, target_path, actual_src, actual_path)
    ctx.dbg(target_path, f'tmp_paths: {tmp_paths}')
    if tmp_paths:
      is_changed = False # now determine if any product has actually changed.
      for tmp_path in tmp_paths:
        is_changed |= update_product_with_tmp(ctx, src, tmp_path)
      return is_changed
    size, mtime, file_hash = 0, 0, None # no product.
  else: # not is_changed.
    file_hash = old.hash
  return update_deps_and_record(ctx, target_path, actual_path,
    is_changed=is_changed, size=size, mtime=mtime, file_hash=file_hash, src=src, old=old)


def expanded_wild_deps(ctx, target, src):
  wild_deps = ctx.db.get_record(src).wild_deps
  if not wild_deps: return
  m = match_wilds(path_stem(src), target)
  bindings = m.groupdict()
  for wild_dep in wild_deps:
    yield wild_dep.format(**bindings)


def update_product_with_tmp(ctx: Ctx, src: str, tmp_path: str):
  product_path, ext = split_stem_ext(tmp_path)
  if ext not in (out_ext, tmp_ext):
    error(tmp_path, f'product output path has unexpected extension: {ext!r}')
  if not is_product_path(product_path):
     error(product_path, 'product path is not in build dir.')
  target_path = product_path[len(build_dir_slash):]
  size, mtime, old = calc_size_mtime_old(ctx, target_path, tmp_path)
  file_hash = hash_for_path(tmp_path, size, max_hash_size)
  is_changed = (size != old.size or size > max_hash_size or file_hash != old.hash)
  if is_changed:
    ctx.db.delete_record(target_path=target_path) # delete metadata if it exists, just before overwrite, in case muck fails before update.
  move_file(tmp_path, product_path, overwrite=True) # move regardless; if not changed, just cleans up the identical tmp file.
  note(target_path, f"product {'changed' if is_changed else 'did not change'}; {format_byte_count(size)}.")
  return update_deps_and_record(ctx, target_path, product_path,
    is_changed=is_changed, size=size, mtime=mtime, file_hash=file_hash, src=src, old=old)


def update_non_product(ctx: Ctx, target_path: str, is_changed: bool, size, mtime, old) -> bool:
  ctx.dbg(target_path, 'update_non_product')
  file_hash = hash_for_path(target_path, size, max_hash_size) # must be calculated in all cases.
  if not is_changed: # all we know so far is that it exists and status as a source has not changed.
    is_changed = (size != old.size or file_hash != old.hash)
    if is_changed: # this is more interesting; report.
      note(target_path, 'source changed.')

  return update_deps_and_record(ctx, target_path, target_path,
    is_changed=is_changed, size=size, mtime=mtime, file_hash=file_hash, src=None, old=old)


def update_deps_and_record(ctx, target_path: str, actual_path: str,
  is_changed: bool, size: int, mtime: int, file_hash: Optional[str], src: str, old: TargetRecord) -> bool:
  ctx.dbg(target_path, 'update_deps_and_record')
  if is_changed:
    deps, wild_deps = calc_dependencies(actual_path, ctx.dir_names)
    for dep in deps:
      try: validate_target(dep)
      except InvalidTarget as e:
        exit(f'muck error: {target_path}: invalid dependency: {e.target!r}: {e.msg}')
      # TODO: validate wild_deps? how?
  else:
    deps = old.deps
    wild_deps = old.wild_deps
  for dep in deps:
    is_changed |= update_dependency(ctx, dep, dependent=target_path)

  ctx.statuses[target_path] = is_changed # replace sentinal with final value.
  if is_changed:
    record = TargetRecord(path=target_path, size=size, mtime=mtime, hash=file_hash, src=src, deps=deps, wild_deps=wild_deps)
    ctx.dbg(target_path, f'updated record:\n  {record}')
    if is_empty_record(old):
      ctx.db.insert_record(record)
    else:
      ctx.db.update_record(record)

  return is_changed


# Dependency calculation.

def calc_dependencies(path, dir_names):
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


def list_dependencies(src_path, src_file, dir_names):
  'Calculate dependencies for .list files.'
  lines = (line.strip() for line in src_file)
  return [l for l in lines if l and not l.startswith('#')]


def mush_dependencies(src_path, src_file, dir_names):
  'Calculate dependencies for .mush files.'
  for line in src_file:
    for token in shlex.split(line):
      if path_ext(token):
        yield token


try: from pat import pat_dependencies
except ImportError:
  def pat_dependencies(src_path, src_file, dir_names):
    error(src_path, '`pat` is not installed; run `pip install pat-tool`.')


try: from writeup.v0 import writeup_dependencies
except ImportError:
  def writeup_dependencies(src_path, src_file, dir_names):
    error(src_path, '`writeup` is not installed; run `pip install writeup-tool`.')


dependency_fns = {
  '.list' : list_dependencies,
  '.mush' : mush_dependencies,
  '.pat' : pat_dependencies,
  '.py' : py_dependencies,
  '.wu' : writeup_dependencies,
}


# Build.


def build_product(ctx, target_path: str, src_path: str, prod_path: str) -> bool:
  '''
  Run a source file, producing zero or more products.
  Return a list of produced product paths.
  '''
  src_ext = path_ext(src_path)
  try:
    build_tool = build_tools[src_ext]
  except KeyError:
    # TODO: fall back to generic .deps file.
    error(target_path, f'unsupported source file extension: {src_ext!r}')
  prod_path_out = prod_path + out_ext
  prod_path_tmp = prod_path + tmp_ext
  remove_file_if_exists(prod_path_out)
  remove_file_if_exists(prod_path_tmp)

  if not build_tool:
    note(target_path, 'no op.')
    return False # no product.

  prod_dir = path_dir(prod_path)
  make_dirs(prod_dir)

  # Extract args from the combination of wilds in the source and the matching target.
  m = match_wilds(target_path_for_source(src_path), target_path)
  if m is None:
    error(target_path, f'internal error: match failed; src_path: {src_path!r}')
  argv = [src_path] + list(m.groups())
  cmd = build_tool + argv

  try: env_fn = build_tool_env_fns[src_ext]
  except KeyError: env = None
  else:
    env = os.environ.copy()
    custom_env = env_fn()
    env.update(custom_env)

  note(target_path, f"building: `{' '.join(shlex.quote(w) for w in cmd)}`")
  out_file = open(prod_path_out, 'wb')
  time_start = time.time()
  code = runC(cmd, env=env, out=out_file)
  time_elapsed = time.time() - time_start
  out_file.close()
  if code != 0:
    error(target_path, f'build failed with code: {code}')

  def cleanup_out():
    if file_size(prod_path_out) == 0:
      remove_file(prod_path_out)
    else:
      warn(target_path, f'wrote data directly to `{prod_path_tmp}`;\n  ignoring output captured in `{prod_path_out}`')

  manif_path = manifest_path(argv)
  try: f = open(manif_path)
  except FileNotFoundError: # no list.
    if not path_exists(prod_path_tmp):
      via = 'stdout'
      tmp_paths = [prod_path_out]
    else:
      via = 'tmp'
      tmp_paths = [prod_path_tmp]
      cleanup_out()
  else:
    via = 'manifest'
    tmp_paths = list(line[:-1] for line in f) # strip newlines.
    cleanup_out()
    if prod_path_tmp not in tmp_paths:
      error(target_path, f'product does not appear in manifest ({len(tmp_paths)} records): {manif_path}')
    remove_file(manif_path)
  time_msg = f'{time_elapsed:0.2f} seconds ' if ctx.report_times else ''
  note(target_path, f'finished: {time_msg}(via {via}).')
  return tmp_paths


_pythonV_V = 'python' + '.'.join(str(v) for v in sys.version_info[:2])
build_tools = {
  '.list' : [], # no-op.
  '.mush' : ['mush'],
  '.pat' : ['pat', 'apply'],
  '.py' : [_pythonV_V],
    # use the same version of python that muck is running under.
  '.wu' : ['writeup'],
}


def py_env():
  return { 'PYTHONPATH' : current_dir() }

build_tool_env_fns = {
  '.py' : py_env
}


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
  except IsADirectoryError: error(path, 'expected a file but found a directory')
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


def calc_size_mtime_old(ctx: Ctx, target_path: str, actual_path: str) -> tuple:
  try:
    size, mtime = file_size_and_mtime(actual_path)
  except FileNotFoundError:
    size, mtime = 0, 0
  ctx.dbg(target_path, f'size: {size}; mtime: {mtime}')
  return size, mtime, ctx.db.get_record(target_path=target_path)


def file_size_and_mtime(path):
  stats = os.stat(path)
  return (stats.st_size, stats.st_mtime)


def source_for_target(ctx, target_path):
  '''
  Find the unique source path whose name matches `target_path`, or else error.
  '''
  src_dir, prod_name = split_dir_name(target_path)
  src_name = source_candidate(ctx, target_path, src_dir, prod_name)
  src = path_join(src_dir, src_name)
  assert src != target_path
  return src


def source_candidate(ctx, target_path, src_dir, prod_name):
  src_dir = src_dir or '.'
  try: src_dir_names = list_dir_filtered(src_dir, cache=ctx.dir_names)
  except FileNotFoundError: error(target_path, f'no such source directory: `{src_dir}`')
  candidates = list(filter_source_names(src_dir_names, prod_name))
  if len(candidates) == 1:
    return candidates[0]
  # error.
  deps = ', '.join(sorted(ctx.dependents[target_path])) or target_path
  if len(candidates) == 0:
    error(deps, f'no source candidates matching `{target_path}` in `{src_dir}`')
  else:
    error(deps, f'multiple source candidates matching `{target_path}`: {candidates}')


def list_dir_filtered(src_dir, cache):
  '''
  Given src_dir, Cache and return the list of names that might be source files.
  TODO: eventually this should be replaced by using os.scandir.
  '''
  try: return cache[src_dir]
  except KeyError: pass
  names = [n for n in list_dir(src_dir, hidden=False)
    if n not in reserved_names and path_ext(n) not in reserved_or_ignored_exts]
  cache[dir] = names
  return names


def filter_source_names(names, prod_name):
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


def note(path, *items):
  errL(f'muck note: {path}: ', *items)

def warn(path, *items):
  errL(f'muck WARNING: {path}: ', *items)

def error(path, *items):
  errL(f'muck error: {path}: ', *items)
  exit(1)
