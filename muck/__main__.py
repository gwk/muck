#!/usr/bin/env python3
# Dedicated to the public domain under CC0: https://creativecommons.org/publicdomain/zero/1.0/.

import sys
assert sys.version_info.major == 3 # python 2 is not supported.

import base64
import json
import os
import shlex
import time

from argparse import ArgumentParser
from collections import defaultdict, namedtuple
from hashlib import sha256
from pithy.fs import (current_dir, file_size, is_file, list_dir, make_dirs, move_file,
  path_dir, path_exists, path_ext, path_join, path_stem,
  remove_dir_contents, remove_file, remove_file_if_exists, split_dir_name, split_stem_ext)
from pithy.io import errF, errFL, failF, outL, outZ
from pithy.json_utils import load_json, write_json
from pithy.string_utils import format_byte_count_dec
from pithy.task import runC
from typing import Optional

from . import (actual_path_for_target, build_dir, build_dir_slash, db_name, has_wilds,
  ignored_exts, is_product_path, is_wild, manifest_path, match_wilds,
  paths_from_range_items, reserved_exts, product_path_for_target, reserved_names, target_path_for_source)
from .py_deps import py_dependencies


def main():
  arg_parser = ArgumentParser(description='muck around with dependencies.')
  arg_parser.add_argument('targets', nargs='*', default=['index.html'], help='target file names.')
  arg_parser.add_argument('-dbg', action='store_true')
  args = arg_parser.parse_args()

  if args.dbg:
    def dbgF(path, fmt, *items):
      errFL('muck dbg: {}: ' + fmt, path, *items)
  else:
    def dbgF(path, fmt, *items): pass

  command_needs_ctx, command_fn = commands.get(args.targets[0], (None, None))

  if command_fn and not command_needs_ctx:
    return command_fn(args.targets[1:])

  make_dirs(build_dir) # required for load_db.

  ctx = Ctx(db=load_db(), statuses={}, dir_names={}, dependents=defaultdict(set), dbgF=dbgF)

  if command_fn:
    assert command_needs_ctx
    command_fn(ctx, args.targets[1:])
  else: # no command; default behavior is to update each specified target.
    for target in args.targets:
      update_dependency(ctx, target, dependent=None, force=True)



Ctx = namedtuple('Ctx', 'db statuses dir_names dependents dbgF')
# info: dict (target_path: str => TargetInfo).
# statuses: dict (target_path: str => is_changed: bool|Ellipsis).
# dir_names: dict (dir_path: str => names: [str]).
# dbgF: debug printing function.


# Build info.

# Muck stores build information in a file within the build directory.
db_path = path_join(build_dir, db_name)

TargetInfo = namedtuple('TargetInfo', 'size mtime hash src_path deps')
empty_info = TargetInfo(size=None, mtime=None, hash=None, src_path=None, deps=())

def all_deps_for_target(ctx, target):
  info = ctx.db[target]
  if info.src_path is not None:
    return [info.src_path] + info.deps
  else:
    return info.deps


'''
Database format:
 'target': target path (not product paths prefixed with build_dir).
 'val: TargetInfo.
 src_path is None for non-product sources.
 Each dependency is a target path.
 TODO: save info about muck version itself in the dict under reserved name 'muck'.
'''

def load_db():
  try:
    with open(db_path) as f:
      return load_json(f, types=(TargetInfo,))
  except FileNotFoundError:
    return {}
  except json.JSONDecodeError as e:
    warnF(info_path, 'JSON decode failed; ignoring build info ({}).', e)
    return {}


def save_db(db: dict):
  with open(db_path, 'w') as f:
    write_json(f, { k: target_info._asdict() for k, target_info in db.items() })


# Commands.


def muck_clean(ctx, args):
  '''
  `muck clean` command.
  '''
  if not args:
    failF('muck clean error: clean command takes specific target arguments; use clean-all to remove all products.')
  for arg in args:
    if arg not in ctx.db:
      errFL('muck clean note: {}: skipping unknown target.', arg)
      continue
    prod_path = product_path_for_target(arg)
    remove_file_if_exists(prod_path)
    del ctx.db[arg]
  save_db(ctx.db)


def muck_clean_all(args):
  '''
  `muck clean-all` command.
  '''
  if args:
    failF('muck clean-all error: clean-all command no arguments; use clean to remove individual products.')
  remove_dir_contents(build_dir)


def muck_deps(ctx, args):
  '''
  `muck deps` command: print dependency information.
  '''
  args = frozenset(args) # deduplicate arguments.
  targets = args or frozenset(ctx.db); # default to all known targets.

  for target in sorted(targets):
    update_dependency(ctx, target, dependent=None)

  roots = set(args) or { t for t in targets if t not in ctx.dependents }
  roots.update(t for t, s in ctx.dependents.items() if len(s) > 1)

  def visit(depth, target):
    deps = all_deps_for_target(ctx, target)
    dependents = ctx.dependents[target]
    if depth == 0 and len(dependents) > 0:
      suffix = ' (dependents: {}):'.format(' '.join(sorted(dependents)))
    elif len(dependents) > 1: suffix = '*'
    elif len(deps) == 0:      suffix = ''
    else:                     suffix = ':'
    outL('  ' * depth, target, suffix)
    if depth > 0 and len(dependents) > 1: return
    for dep in deps:
      visit(depth + 1, dep)

  for root in sorted(roots):
    outL()
    visit(0, root)


def muck_patch(ctx, args):

  if not len(args) in (1, 2):
    failF('''\
muck patch error: patch command takes one or two arguments. usage:

  muck patch [original_target] [target]
    creates a new target by copying either the source or product of the original to _build/[target],
    and then creates an empty [target].pat.

  muck patch [target.pat]
    update the patch file with the diff of the previously specified original and target.
''')

  if len(args) == 2: # create new patch.
    orig_target_path, target_path = args
    if orig_target_path.endswith('.pat'):
      errFL('muck patch error: original should not be a patch file: {}', orig_target_path)
    if target_path.endswith('.pat'):
      errFL('muck patch error: {} {}: target should not be a patch file: {}', target_path)
    patch_path = target_path + '.pat'
    if path_exists(patch_path):
      failF('muck patch error: {}: patch already exists.', patch_path)
    update_dependency(ctx, orig_target_path, dependent=None)
    orig_path = actual_path_for_target(orig_target_path)
    prod_path = product_path_for_target(target_path)
    if path_exists(prod_path):
      errFL('muck patch note: product already exists: {}', prod_path)
    else:
      errFL('muck patch note: copying original to product: {} -> {}', orig_path, prod_path)
      copy_file(orig_path, prod_path)

  else: # update existing patch.
    patch_path = args[0]
    if path_ext(patch_path) != '.pat':
      failF('muck patch error: argument does not specify a .pat file: {!r}', patch_path)
    deps = pat_dependencies(patch_path, open(patch_path), {})
    orig_target_path = deps[0]
    update_dependency(ctx, orig_target_path, dependent=None)
    orig_path = actual_path_for_target(orig_target_path)
    target_path = path_stem(patch_path)
    prod_path = product_path_for_target(target_path)

  # update patch (both cases).
  patch_path_tmp = patch_path + '.tmp'
  cmd = ['pat', 'diff', orig_path, prod_path]
  errFL('muck patch note: diffing: `{}`', ' '.join(shlex.quote(w) for w in cmd))
  with open(patch_path_tmp, 'wb') as f:
    code = runC(cmd, out=f)
  move_file(patch_path_tmp, patch_path, overwrite=True)

  if len(args) == 1: # updated existing patch.
    # need to remove or update the target info to avoid the 'did you mean to patch?' safeguard.
    # for now, just delete it to be safe; this makes the target look stale.
    try:
      del ctx.db[target_path]
      save_db(ctx.db)
    except KeyError: pass


commands = {
  # values are (needs_ctx, fn).
  'clean'     : (True,  muck_clean),
  'clean-all' : (False, muck_clean_all),
  'deps'      : (True,  muck_deps),
  'patch'     : (True,  muck_patch),
}


# Default update functionality.


def update_dependency(ctx: Ctx, target_path: str, dependent: Optional[str], force=False) -> bool:
  '''
  returns is_changed.
  '''
  target_ext = path_ext(target_path)

  if not target_path.strip():
    failF(repr(target_path), 'invalid target name.')
  if target_path in reserved_names:
    failF(target_path, 'target name is reserved; please rename the target.')
  if target_ext in reserved_exts:
    failF(target_path, 'target name has reserved extension; please rename the target.')

  if dependent is not None:
    ctx.dependents[target_path].add(dependent)

  try: # if in ctx.statuses, this path has already been visited on this run.
    status = ctx.statuses[target_path]
    if status is Ellipsis: # recursion sentinal.
      involved_paths = sorted(path for path, status in ctx.statuses.items() if status is Ellipsis)
      failF(target_path, 'target has circular dependency; involved paths:\n  {}',
        '\n  '.join(involved_paths))
    return status
  except KeyError: pass

  ctx.statuses[target_path] = Ellipsis # recursion sentinal is replaced before return.

  ctx.dbgF(target_path, 'examining... (dependent={})', dependent)

  is_product = not path_exists(target_path)
  actual_path = product_path_for_target(target_path) if is_product else target_path
  size, mtime, old = calc_size_mtime_old(ctx, target_path, actual_path)
  has_old_file = (mtime is not None)
  has_old_info = (old.mtime is not None)

  is_changed = force or (not has_old_file) or (not has_old_info)

  if has_old_info:
    old_is_product = bool(old.src_path)
    if is_product != old_is_product: # nature of the target changed.
      noteF(target_path, 'target is {} a product.', 'now' if is_product else 'no longer')
      is_changed = True
    if not has_old_file and target_ext: # product was deleted and not a phony target.
      noteF(target_path, 'old product was deleted.')

  if is_product:
    if has_old_file and has_old_info:
      check_product_not_modified(ctx, target_path, actual_path, size, mtime, old)
    return update_product(ctx, target_path, actual_path, is_changed, size, mtime, old)
  else:
    return update_non_product(ctx, target_path, is_changed, size, mtime, old)


def check_product_not_modified(ctx, target_path, actual_path, size, mtime, old):
  # existing product should not have been modified since info was stored.
  # if the size changed then it was definitely modified.
  # otherwise, if the mtime is unchanged, assume that the file is ok, for speed.
  # if the mtime changed, check the hash;
  # the user might have made an accidental edit and then reverted it,
  # and we would rather compute the hash than report a false problem.
  if size != old.size or (mtime != old.mtime and hash_for_path(actual_path) != old.hash):
    ctx.dbgF(target_path, 'size: {} -> {}; mtime: {} -> {}', old.size, size, old.mtime, mtime)
    # TODO: change language depending on whether product is derived from a patch?
    failF(target_path, 'existing product has changed; did you mean to update a patch?\n'
      '  Otherwise, save your changes if necessary and then `muck clean {}`.',
      target_path)


def update_product(ctx: Ctx, target_path: str, actual_path, is_changed, size, mtime, old) -> bool:
  ctx.dbgF(target_path, 'update_product')
  src_path = source_for_target(ctx, target_path)
  if old.src_path != src_path:
    is_changed = True
    if old.src_path:
      noteF(target_path, 'source path of target product changed\n  was: {}\n  now: {}',
        old.src_path, src_path)
  is_changed |= update_dependency(ctx, src_path, dependent=target_path)

  if is_changed: # must rebuild product.
    actual_src_path = actual_path_for_target(src_path) # source might itself be a product.
    tmp_paths = build_product(ctx, target_path, actual_src_path, actual_path)
    ctx.dbgF(target_path, 'tmp_paths: {}', tmp_paths)
    if tmp_paths:
      is_changed = False # now determine if any product has actually changed.
      for tmp_path in tmp_paths:
        is_changed |= update_product_with_tmp(ctx, src_path, tmp_path)
      return is_changed
    size, mtime, file_hash = None, None, None # no product.
  else: # not is_changed.
    file_hash = old.hash
  return update_deps_and_info(ctx, target_path, actual_path, is_changed, size, mtime, file_hash, src_path, old.deps)


def update_product_with_tmp(ctx: Ctx, src_path: str, tmp_path: str):
  product_path, ext = split_stem_ext(tmp_path)
  if ext not in ('.tmp', '.out'):
    failF(tmp_path, 'product output path has unexpected extension: {!r}', ext)
  if not is_product_path(product_path):
     failF(product_path, 'product path is not in build dir.')
  target_path = product_path[len(build_dir_slash):]
  size, mtime, old = calc_size_mtime_old(ctx, target_path, tmp_path)
  ctx.db.pop(target_path, None) # delete metadata if it exists, just before overwrite.
  move_file(tmp_path, product_path, overwrite=True)
  file_hash = hash_for_path(product_path)
  is_changed = (size != old.size or file_hash != old.hash)
  noteF(target_path, 'product {}; {}.', 'changed' if is_changed else 'did not change', format_byte_count_dec(size))
  return update_deps_and_info(ctx, target_path, product_path, is_changed, size, mtime, file_hash, src_path, old.deps)


def update_non_product(ctx: Ctx, target_path: str, is_changed: bool, size, mtime, old) -> bool:
  ctx.dbgF(target_path, 'update_non_product')
  file_hash = hash_for_path(target_path) # must be calculated in all cases.
  if not is_changed: # all we know so far is that it exists and status as a source has not changed.
    is_changed = (size != old.size or file_hash != old.hash)
    if is_changed: # this is more interesting; report.
      noteF(target_path, 'source changed.')

  return update_deps_and_info(ctx, target_path, target_path, is_changed, size, mtime, file_hash, None, old.deps)


def update_deps_and_info(ctx, target_path: str, actual_path: str, is_changed, size, mtime, file_hash, src_path, old_deps) -> bool:
  ctx.dbgF(target_path, 'update_deps_and_info')
  if is_changed:
    deps = calc_dependencies(actual_path, ctx.dir_names)
  else:
    deps = old_deps
  for dep in deps:
    is_changed |= update_dependency(ctx, dep, dependent=target_path)

  ctx.statuses[target_path] = is_changed # replace sentinal with final value.
  if is_changed:
    info = TargetInfo(size=size, mtime=mtime, hash=file_hash, src_path=src_path, deps=deps)
    ctx.dbgF(target_path, 'updated info:\n  {}', info)
    ctx.db[target_path] = info
    # writing the entire dict at every step will not scale well;
    # at that point we should probably move to sqlite or similar anyway.
    save_db(ctx.db)

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
    return []
  with open(path) as f:
    return sorted(dep_fn(path, f, dir_names))


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
    failF(src_path, '`pat` is not installed; run `pip install pat-tool`.')


try: from writeup.v0 import writeup_dependencies
except ImportError:
  def writeup_dependencies(src_path, src_file, dir_names):
    failF(src_path, '`writeup` is not installed; run `pip install writeup-tool`.')


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
    failF(target_path, 'unsupported source file extension: `{}`', src_ext)
  prod_path_out = prod_path + '.out'
  prod_path_tmp = prod_path + '.tmp'
  remove_file_if_exists(prod_path_out)
  remove_file_if_exists(prod_path_tmp)

  if not build_tool:
    noteF(target_path, 'no op.')
    return False # no product.

  prod_dir = path_dir(prod_path)
  make_dirs(prod_dir)

  # Extract args from the combination of wilds in the source and the matching target.
  m = match_wilds(target_path_for_source(src_path), target_path)
  argv = [src_path] + list(m.groups())
  cmd = build_tool + argv

  try: env_fn = build_tool_env_fns[src_ext]
  except KeyError: env = None
  else:
    env = os.environ.copy()
    custom_env = env_fn()
    env.update(custom_env)

  noteF(target_path, 'building: `{}`', ' '.join(shlex.quote(w) for w in cmd))
  out_file = open(prod_path_out, 'wb')
  time_start = time.time()
  code = runC(cmd, env=env, out=out_file)
  time_end = time.time()
  out_file.close()
  if code != 0:
    failF(target_path, 'build failed with code: {}', code)

  def cleanup_out():
    if file_size(prod_path_out) == 0:
      remove_file(prod_path_out)
    else:
      warnF(target_path, 'wrote data directly to `{}`;\n  ignoring output captured in `{}`', prod_path_tmp, prod_path_out)

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
    if ('%' not in prod_path_tmp) and prod_path_tmp not in tmp_paths:
      failF(target_path, 'product does not appear in manifest.')
    remove_file(manif_path)
  noteF(target_path, 'finished: {:0.2f} seconds (via {}).', time_end - time_start, via)
  return tmp_paths


build_tools = {
  '.list' : [], # no-op.
  '.mush' : ['mush'],
  '.pat' : ['pat', 'apply'],
  '.py' : ['python{}.{}'.format(sys.version_info.major, sys.version_info.minor)],
    # use the same version of python that muck is running under.
  '.wu' : ['writeup'],
}


def py_env():
  return { 'PYTHONPATH' : current_dir() }

build_tool_env_fns = {
  '.py' : py_env
}


# Utilities.


def hash_for_path(path, max_chunks=sys.maxsize):
  '''
  return a hash string for the contents of the file at the given path.
  '''
  try:
    f = open(path, 'rb')
  except IsADirectoryError:
    failF(path, 'expected a file but found a directory')
  h = sha256()
  # a quick timing experiment suggested that chunk sizes larger than this are not faster.
  chunk_size = 1 << 16
  for i in range(max_chunks):
    chunk = f.read(chunk_size)
    if not chunk: break
    h.update(chunk)
  d = h.digest()
  return base64.urlsafe_b64encode(d).decode()


def calc_size_mtime_old(ctx: Ctx, target_path: str, actual_path: str) -> tuple:
  try:
    size, mtime = file_size_and_mtime(actual_path)
  except FileNotFoundError:
    size, mtime = None, None
  ctx.dbgF(target_path, 'size: {}; mtime: {}', size, mtime)
  old = ctx.db.get(target_path, empty_info)
  return size, mtime, old


def file_size_and_mtime(path):
  stats = os.stat(path)
  return (stats.st_size, stats.st_mtime)


def source_for_target(ctx, target_path):
  '''
  Find the unique source path to whose name matches `target_path`, or else error.
  '''
  src_dir, prod_name = split_dir_name(target_path)
  src_name = source_candidate(ctx, target_path, src_dir, prod_name)
  src_path = path_join(src_dir, src_name)
  assert src_path != target_path
  return src_path


def source_candidate(ctx, target_path, src_dir, prod_name):
  src_dir_names = list_dir_filtered(src_dir or '.', cache=ctx.dir_names)
  candidates = list(filter_source_names(src_dir_names, prod_name))
  if len(candidates) == 1:
    return candidates[0]
  # error.
  deps = ', '.join(sorted(ctx.dependents[target_path])) or target_path
  if len(candidates) == 0:
    failF(deps, 'no source candidates matching `{}`', target_path)
  else:
    failF(deps, 'multiple source candidates matching `{}`: {}', target_path, candidates)


def list_dir_filtered(src_dir, cache):
  '''
  Given src_dir, Cache and return the list of names that might be source files.
  TODO: eventually this should be replaced by using os.scandir.
  '''
  try: return cache[src_dir]
  except KeyError: pass
  names = [n for n in list_dir(src_dir) if n not in reserved_names and not n.startswith('.')]
  if cache is not None:
    cache[dir] = names
  return names


def filter_source_names(names, prod_name):
  '''
  given product name "x.txt", match all of the following:
  * x.txt.py
  * x.py
  * %.txt.py
  * %.py

  There are several concerns that make this matching complex.
  * Muck allows wildcards in script names.
    This allows a single script to produce many targets for corresponding sources.
  * A source might itself be the product of another source.
  '''
  prod = prod_name.split('.')
  for src_name in names:
    src = src_name.split('.')
    if len(src) <= len(prod): continue
    if all(match_wilds(*p) for p in zip(src, prod)): # zip stops when src is exhausted.
      yield '.'.join(src[:len(src)+1]) # the immediate source name has just one extension added.


def noteF(path, fmt, *items):
  errF('muck note: {}: ', path)
  errFL(fmt, *items)

def warnF(path, fmt, *items):
  errF('muck WARNING: {}: ', path)
  errFL(fmt, *items)

def failF(path, fmt, *items):
  errF('muck error: {}: ', path)
  errFL(fmt, *items)
  exit(1)


if __name__ == '__main__': main()

