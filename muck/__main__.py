#!/usr/bin/env python3
# Dedicated to the public domain under CC0: https://creativecommons.org/publicdomain/zero/1.0/.

'''
Muck build program.
'''

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
from pithy.string_utils import format_byte_count
from pithy.task import runC
from typing import Optional

from .db import TargetRecord, empty_record, is_empty_record, DB, DBError
from .constants import build_dir, build_dir_slash, db_name, db_path, ignored_exts, out_ext, reserved_exts, tmp_ext, reserved_names
from .paths import actual_path_for_target, is_product_path, manifest_path, match_wilds,product_path_for_target, target_path_for_source
from .py_deps import py_dependencies


def main():
  arg_parser = ArgumentParser(description='muck around with dependencies.')
  arg_parser.add_argument('targets', nargs='*', default=['index.html'], help='target file names.')
  arg_parser.add_argument('-no-times', action='store_true', help='do not report process times.')
  arg_parser.add_argument('-dbg', action='store_true')
  arg_parser.add_argument('-force', action='store_true')

  args = arg_parser.parse_args()

  if args.dbg:
    def dbgF(path, fmt, *items):
      errFL('muck dbg: {}: ' + fmt, path, *items)
  else:
    def dbgF(path, fmt, *items): pass

  command_needs_ctx, command_fn = commands.get(args.targets[0], (None, None))

  if command_fn and not command_needs_ctx:
    return command_fn(args.targets[1:])

  make_dirs(build_dir) # required to create new DB.

  ctx = Ctx(db=DB(path=db_path), statuses={}, dir_names={}, dependents=defaultdict(set),
    report_times=(not args.no_times), dbgF=dbgF)

  if command_fn:
    assert command_needs_ctx
    command_fn(ctx, args.targets[1:])
  else: # no command; default behavior is to update each specified target.
    for target in args.targets:
      update_dependency(ctx, target, dependent=None, force=args.force)



Ctx = namedtuple('Ctx', 'db statuses dir_names dependents report_times dbgF')
# db: DB.
# statuses: dict (target_path: str => is_changed: bool|Ellipsis).
# dir_names: dict (dir_path: str => names: [str]).
# dependents: defaultdict(set) (target_path: str => depedents).
# report_times: bool.
# dbgF: debug printing function.


# Commands.


def muck_clean(ctx, args):
  '''
  `muck clean` command.
  '''
  if not args:
    failF('muck clean error: clean command takes specific target arguments; use clean-all to remove all products.')
  for target in args:
    if not ctx.db.contains_record(target_path=target):
      errFL('muck clean note: {}: skipping unknown target.', target)
      continue
    prod_path = product_path_for_target(target)
    remove_file_if_exists(prod_path)
    ctx.db.delete_record(target_path=target)



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
  targets = args or frozenset(ctx.db.all_target_names())

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
  patch_path_tmp = patch_path + tmp_ext
  cmd = ['pat', 'diff', orig_path, prod_path]
  errFL('muck patch note: diffing: `{}`', ' '.join(shlex.quote(w) for w in cmd))
  with open(patch_path_tmp, 'wb') as f:
    code = runC(cmd, out=f)
  move_file(patch_path_tmp, patch_path, overwrite=True)

  if len(args) == 1: # updated existing patch.
    # need to remove or update the target record to avoid the 'did you mean to patch?' safeguard.
    # for now, just delete it to be safe; this makes the target look stale.
    try:
      ctx.db.delete_record(target_path=target_path)
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
  has_old_file = (mtime > 0)
  has_old_record = not is_empty_record(old)

  is_changed = force or (not has_old_file) or (not has_old_record)

  if has_old_record:
    old_is_product = (old.src is not None)
    if is_product != old_is_product: # nature of the target changed.
      noteF(target_path, 'target is {} a product.', 'now' if is_product else 'no longer')
      is_changed = True
    if not has_old_file and target_ext: # product was deleted and not a phony target.
      noteF(target_path, 'old product was deleted.')

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
  if size != old.size or (mtime != old.mtime and hash_for_path(actual_path) != old.hash):
    ctx.dbgF(target_path, 'size: {} -> {}; mtime: {} -> {}', old.size, size, old.mtime, mtime)
    # TODO: change language depending on whether product is derived from a patch?
    failF(target_path, 'existing product has changed; did you mean to update a patch?\n'
      '  Otherwise, save your changes if necessary and then `muck clean {}`.',
      target_path)


def update_product(ctx: Ctx, target_path: str, actual_path, is_changed, size, mtime, old) -> bool:
  ctx.dbgF(target_path, 'update_product')
  src = source_for_target(ctx, target_path)
  ctx.dbgF(target_path, 'src: {}', src)
  if old.src != src:
    is_changed = True
    if old.src:
      noteF(target_path, 'source path of target product changed\n  was: {}\n  now: {}', old.src, src)
  is_changed |= update_dependency(ctx, src, dependent=target_path)

  if is_changed: # must rebuild product.
    actual_src = actual_path_for_target(src) # source might itself be a product.
    tmp_paths = build_product(ctx, target_path, actual_src, actual_path)
    ctx.dbgF(target_path, 'tmp_paths: {}', tmp_paths)
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


def update_product_with_tmp(ctx: Ctx, src: str, tmp_path: str):
  product_path, ext = split_stem_ext(tmp_path)
  if ext not in (out_ext, tmp_ext):
    failF(tmp_path, 'product output path has unexpected extension: {!r}', ext)
  if not is_product_path(product_path):
     failF(product_path, 'product path is not in build dir.')
  target_path = product_path[len(build_dir_slash):]
  size, mtime, old = calc_size_mtime_old(ctx, target_path, tmp_path)
  file_hash = hash_for_path(tmp_path)
  is_changed = (size != old.size or file_hash != old.hash)
  if is_changed:
    ctx.db.delete_record(target_path=target_path) # delete metadata if it exists, just before overwrite, in case muck fails before update.
  move_file(tmp_path, product_path, overwrite=True) # move regardless; if not changed, just cleans up the identical tmp file.
  noteF(target_path, 'product {}; {}.', 'changed' if is_changed else 'did not change', format_byte_count(size))
  return update_deps_and_record(ctx, target_path, product_path,
    is_changed=is_changed, size=size, mtime=mtime, file_hash=file_hash, src=src, old=old)


def update_non_product(ctx: Ctx, target_path: str, is_changed: bool, size, mtime, old) -> bool:
  ctx.dbgF(target_path, 'update_non_product')
  file_hash = hash_for_path(target_path) # must be calculated in all cases.
  if not is_changed: # all we know so far is that it exists and status as a source has not changed.
    is_changed = (size != old.size or file_hash != old.hash)
    if is_changed: # this is more interesting; report.
      noteF(target_path, 'source changed.')

  return update_deps_and_record(ctx, target_path, target_path,
    is_changed=is_changed, size=size, mtime=mtime, file_hash=file_hash, src=None, old=old)


def update_deps_and_record(ctx, target_path: str, actual_path: str,
  is_changed: bool, size: int, mtime: int, file_hash: Optional[str], src: str, old: TargetRecord) -> bool:
  ctx.dbgF(target_path, 'update_deps_and_record')
  if is_changed:
    deps = calc_dependencies(actual_path, ctx.dir_names)
  else:
    deps = old.deps
  for dep in deps:
    is_changed |= update_dependency(ctx, dep, dependent=target_path)

  ctx.statuses[target_path] = is_changed # replace sentinal with final value.
  if is_changed:
    record = TargetRecord(path=target_path, size=size, mtime=mtime, hash=file_hash, src=src, deps=deps)
    ctx.dbgF(target_path, 'updated record:\n  {}', record)
    if src or is_empty_record(old):
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
  prod_path_out = prod_path + out_ext
  prod_path_tmp = prod_path + tmp_ext
  remove_file_if_exists(prod_path_out)
  remove_file_if_exists(prod_path_tmp)

  if not build_tool:
    noteF(target_path, 'no op.')
    return False # no product.

  prod_dir = path_dir(prod_path)
  make_dirs(prod_dir)

  # Extract args from the combination of wilds in the source and the matching target.
  m = match_wilds(target_path_for_source(src_path), target_path)
  if m is None:
    failF(target_path, 'internal error: match failed; src_path: {!r}', src_path)
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
  time_elapsed = time.time() - time_start
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
      failF(target_path, 'product does not appear in manifest ({} records): {}',
        len(tmp_paths), manif_path)
    remove_file(manif_path)
  time_msg = '{:0.2f} seconds '.format(time_elapsed) if ctx.report_times else ''
  noteF(target_path, 'finished: {}(via {}).', time_msg, via)
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


def hash_for_path(path: str, max_chunks=sys.maxsize) -> bytes:
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
  return h.digest()


def hash_string(hash: bytes) -> str:
  return base64.urlsafe_b64encode(hash).decode()


def calc_size_mtime_old(ctx: Ctx, target_path: str, actual_path: str) -> tuple:
  try:
    size, mtime = file_size_and_mtime(actual_path)
  except FileNotFoundError:
    size, mtime = 0, 0
  ctx.dbgF(target_path, 'size: {}; mtime: {}', size, mtime)
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
  names = [n for n in list_dir(src_dir, hidden=False)
    if n not in reserved_names and path_ext(n) not in ignored_exts]
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
    if all(match_wilds(*p) for p in zip(src, prod)): # zip stops when prod is exhausted.
      yield '.'.join(src[:len(prod)+1]) # the immediate source name has just one extension added.


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

