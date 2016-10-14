#!/usr/bin/env python3
# Dedicated to the public domain under CC0: https://creativecommons.org/publicdomain/zero/1.0/.

import sys
assert sys.version_info.major == 3 # python 2 is not supported.

import ast
import base64
import json
import os
import re
import shlex
import time

from argparse import ArgumentParser
from collections import defaultdict, namedtuple
from hashlib import sha256
from pat import pat_dependencies
from writeup.v0 import writeup_dependencies
from pithy.io import errF, errFL, failF, outL, outZ, read_json, write_json
from pithy.fs import file_size, is_file, make_dirs, move_file, path_dir, path_exists, path_ext, path_join, path_stem, remove_dir_contents, remove_file, remove_file_if_exists
from pithy.string_utils import format_byte_count_dec
from pithy.task import runC

from muck import actual_path_for_target, build_dir, ignored_exts, info_name, muck_failF, \
reserved_exts, product_path_for_target, reserved_names, source_for_target


TargetInfo = namedtuple('TargetInfo', 'size mtime hash src_path deps')

def target_info_all_deps(info):
  if info.src_path is not None:
    return [info.src_path] + info.deps
  else:
    return info.deps


info_path = path_join(build_dir, info_name)

# info dictionary stores the persistent build information.
# key: target path (not product paths prefixed with build_dir).
# val: TargetInfo.
# src_path is None for non-product sources.
# each dependency is a target path.
# TODO: save info about muck version itself in the dict under reserved name 'muck'.

def load_info():
  try:
    with open(info_path) as f:
      return read_json(f, types=(TargetInfo,))
  except FileNotFoundError:
    return {}
  except json.JSONDecodeError as e:
    warnF(info_path, 'JSON decode failed; ignoring build info ({}).', e)
    return {}


def save_info(info: dict):
  with open(info_path, 'w') as f:
    write_json(f, info)


def noteF(path, fmt, *items):
  errF('muck note: {}: ', path)
  errFL(fmt, *items)

def warnF(path, fmt, *items):
  errF('muck WARNING: {}: ', path)
  errFL(fmt, *items)


def list_dependencies(src_path, src_file, dir_names):
  lines = (line.strip() for line in src_file)
  return [l for l in lines if l and not l.startswith('#')]


def py_dep_call(src_path, node):
  func = node.func
  if not isinstance(func, ast.Attribute): return
  if not isinstance(func.value, ast.Name): return
  # TODO: dispatch to handlers for all known functions.
  # add handler for source_url;
  # this should check that repeated (url, target) pairs are consistent across entire project.
  if func.value.id != 'muck': return
  if func.attr not in ('source', 'transform'): return
  if len(node.args) < 1 or not isinstance(node.args[0], ast.Str):
    muck_failF('{}:{}:{}: muck.{}: first argument must be a string literal.',
      src_path, node.lineno, node.col_offset, func.attr)
  yield node.args[0].s # the string literal value from the ast.Str.


def py_dep_import(src_path, module_name, dir_names):
  src_dir = path_dir(src_path)
  leading_dots_count = re.match('\.*', module_name).end()
  module_parts = ['..'] * leading_dots_count + module_name[leading_dots_count:].split('.')
  module_path = path_join(src_dir, *module_parts) + '.py'
  if is_file(module_path):
    yield module_path


def py_dependencies(src_path, src_file, dir_names):
  'Calculate dependencies of a python3 source file.'
  src_text = src_file.read()
  tree = ast.parse(src_text, src_path)
  for node in ast.walk(tree):
    if isinstance(node, ast.Call):
      yield from py_dep_call(src_path, node)
    elif isinstance(node, ast.Import):
      for alias in node.names:
        yield from py_dep_import(src_path, alias.name, dir_names)
    elif isinstance(node, ast.ImportFrom):
      yield from py_dep_import(src_path, node.module, dir_names)


dependency_fns = {
  '.list' : list_dependencies,
  '.pat' : pat_dependencies,
  '.py' : py_dependencies,
  '.wu' : writeup_dependencies,
}

build_tools = {
  '.list' : [], # no-op.
  '.pat' : ['pat', 'apply'],
  '.py' : ['python{}.{}'.format(sys.version_info.major, sys.version_info.minor)], # use the same version of python that muck is running under.
  '.wu' : ['writeup']
}

def calc_dependencies(path, dir_names):
  ext = path_ext(path)
  try:
    dep_fn = dependency_fns[ext]
  except KeyError:
    return []
  with open(path) as f:
    return sorted(dep_fn(path, f, dir_names))


def hash_for_path(path, max_chunks=sys.maxsize):
  '''
  return a hash string for the contents of the file at the given path.
  '''
  try:
    f = open(path, 'rb')
  except IsADirectoryError:
    muck_failF(path, 'expected a file but found a directory')
  h = sha256()
  # a quick timing experiment suggested that chunk sizes larger than this are not faster.
  chunk_size = 1 << 16
  for i in range(max_chunks):
    chunk = f.read(chunk_size)
    if not chunk: break
    h.update(chunk)
  d = h.digest()
  return base64.urlsafe_b64encode(d).decode()


# commands.

def muck_clean(ctx, args):
  if not args:
    failF('muck clean error: clean command takes specific target arguments; use clean-all to remove all products.')
  for arg in args:
    if arg not in ctx.info:
      errFL('muck clean note: {}: skipping unknown target.', arg)
      continue
    prod_path = product_path_for_target(arg)
    remove_file_if_exists(prod_path)
    del ctx.info[arg]
  save_info(ctx.info)


def muck_clean_all(args):
  if args:
    failF('muck clean-all error: clean-all command no arguments; use clean to remove individual products.')
  remove_dir_contents(build_dir)


def muck_deps(ctx, args):
  set_args = set(args) # deduplicate arguments.
  target_dependents = defaultdict(set)

  def update_and_count_deps(target):
    update_dependency(ctx, target)
    deps = target_info_all_deps(ctx.info[target])
    for dependency in deps:
      target_dependents[dependency].add(target)
      update_and_count_deps(dependency)

  targets = sorted(set_args or ctx.info) # default to all known targets.
  for target in targets:
    update_and_count_deps(target)

  roots = set_args.union(t for t, s in target_dependents.items() if len(s) > 1)

  def visit(depth, target):
    deps = target_info_all_deps(ctx.info[target])
    dependents = target_dependents[target]
    if depth == 0 and len(dependents) > 0:
      suffix = ' (dependents: {}):\n'.format(' '.join(sorted(dependents)))
    elif len(dependents) > 1:
      suffix = '*\n'
    elif len(deps) == 0:
      suffix = '\n'
    elif len(deps) == 1:
      suffix = ':\n'
    else:
      suffix = ':\n'
    indent = '  ' * depth
    outZ(indent, target, suffix)
    if depth > 0 and len(dependents) > 1: return
    for dep in target_info_all_deps(ctx.info[target]):
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
    update_dependency(ctx, orig_target_path)
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
    update_dependency(ctx, orig_target_path)
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
      del ctx.info[target_path]
      save_info(ctx.info)
    except KeyError: pass


commands = {
  # values are (needs_ctx, fn).
  'clean'     : (True,  muck_clean),
  'clean-all' : (False, muck_clean_all),
  'deps'      : (True,  muck_deps),
  'patch'     : (True,  muck_patch),
}


def build_product(info: dict, target_path: str, src_path: str, prod_path: str, use_std_out: bool) -> bool:
  '''
  build a product from a source.
  '''
  src_ext = path_ext(src_path)
  try:
    build_tool = build_tools[src_ext]
  except KeyError:
    # TODO: fall back to generic .deps file.
    muck_failF(target_path, 'unsupported source file extension: `{}`', src_ext)
  prod_path_out = prod_path + '.out'
  prod_path_tmp = prod_path + '.tmp'
  remove_file_if_exists(prod_path_out)
  remove_file_if_exists(prod_path_tmp)
  # TODO: if not use_std_out, then maybe we should remove all products with matching stem?

  if not build_tool:
    noteF(target_path, 'no op.')
    return False # no product.

  prod_dir = path_dir(prod_path)
  make_dirs(prod_dir)
  cmd = build_tool + [src_path, prod_path_tmp]
  noteF(target_path, 'building: `{}`', ' '.join(shlex.quote(w) for w in cmd))
  out_file = open(prod_path_out, 'wb') if use_std_out else None
  time_start = time.time()
  code = runC(cmd, out=out_file)
  time_end = time.time()
  if out_file: out_file.close()
  has_product = True
  if code != 0:
    muck_failF(target_path, 'build failed with code: {}', code)

  def move_to_prod(path):
    info.pop(target_path, None) # delete metadata as we overwrite old file.
    move_file(path, prod_path, overwrite=True)

  via_msg = '.tmp'
  if use_std_out:
    if path_exists(prod_path_tmp):
      move_to_prod(prod_path_tmp)
      if file_size(prod_path_out) == 0:
        remove_file(prod_path_out)
      else:
        warnF(target_path, 'wrote data directly to `{}`;\n  ignoring output captured in `{}`',
          prod_path_tmp, prod_path_out)
    else:
      via_msg = 'stdout'
      move_to_prod(prod_path_out)
  else: # not use_std_out.
    if path_exists(prod_path_tmp):
      move_to_prod(prod_path_tmp)
    elif path_ext(prod_path): # target is not bare (therefore assumed not phony) target.
      muck_failF(target_path, 'process failed to produce product: {}', prod_path_tmp)
    else:
      has_product = False
      noteF(target_path, 'no product.')
  if has_product:
    suffix = '; {} (via {})'.format(format_byte_count_dec(file_size(prod_path)), via_msg)
  else:
    suffix = ''
  noteF(target_path, 'finished: {:0.2f} seconds{}.', time_end - time_start, suffix)
  return has_product


def file_size_and_mtime(path):
  stats = os.stat(path)
  return (stats.st_size, stats.st_mtime)


Ctx = namedtuple('Ctx', 'info statuses dir_names dbgF')
# info: dict (target_path: str => TargetInfo).
# statuses: dict (target_path: str => is_changed: bool|Ellipsis).
# dir_names: dict (dir_path: str => names: [str]).
# dbgF: debug printing function.


def update_dependency(ctx: Ctx, target_path: str, force=False) -> bool:
  '''
  returns is_changed.
  '''
  target_ext = path_ext(target_path)

  if not target_path.strip():
    muck_failF(repr(target_path), 'invalid target name.')
  if target_path in reserved_names:
    muck_failF(target_path, 'target name is reserved; please rename the target.')
  if target_ext in reserved_exts:
    muck_failF(target_path, 'target name has reserved extension; please rename the target.')

  try: # if in ctx.statuses, this path has already been visited on this run.
    status = ctx.statuses[target_path]
    if status is Ellipsis: # recursion sentinal.
      involved_paths = sorted(path for path, status in ctx.statuses.items() if status is Ellipsis)
      muck_failF(target_path, 'target has circular dependency; involved paths:\n  {}',
        '\n  '.join(involved_paths))
    return status
  except KeyError: pass

  ctx.statuses[target_path] = Ellipsis # recursion sentinal is replaced before return.

  ctx.dbgF(target_path, 'examining...')

  is_product = not path_exists(target_path)
  actual_path = product_path_for_target(target_path) if is_product else target_path
  size, mtime, old = calculate_info(ctx, target_path, actual_path)
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


def calculate_info(ctx: Ctx, target_path: str, actual_path: str) -> tuple:
  try:
    size, mtime = file_size_and_mtime(actual_path)
  except FileNotFoundError:
    size, mtime = None, None
  ctx.dbgF(target_path, 'size: {}; mtime: {}', size, mtime)

  try:
    old = ctx.info[target_path]
  except KeyError: # no previous record.
    ctx.dbgF(target_path, 'no old info.')
    old = TargetInfo(None, None, None, None, [])
  else: # have previous record. must check that it is not stale.
    ctx.dbgF(target_path, 'has old info:\n  {}', old)

  return size, mtime, old


def check_product_not_modified(ctx, target_path, actual_path, size, mtime, old):
  # existing product should not have been modified since info was stored.
  # if the size changed then it was definitely modified.
  # otherwise, if the mtime is unchanged, assume that the file is ok, for speed.
  # if the mtime changed, check the hash;
  # the user might have made an accidental edit and then reverted it,
  # and we would rather compute the hash than report a false problem.
  if size != old.size or (mtime != old.mtime and hash_for_path(actual_path) != old.hash):
    ctx.dbgF(target_path, 'size: {} -> {}; mtime: {} -> {}', old.size, size, old.mtime, mtime)
    muck_failF(target_path, 'existing product has changed; did you mean to update a patch?\n'
      '  please save your changes if necessary and then `muck clean {}`.',
      target_path)


def update_product(ctx: Ctx, target_path: str, actual_path, is_changed, size, mtime, old) -> bool:
  src_path, use_std_out = source_for_target(target_path, ctx.dir_names)
  if old.src_path != src_path:
    is_changed = True
    if old.src_path:
      noteF(target_path, 'source path of target product changed\n  was: {}\n  now: {}',
        old.src_path, src_path)
  is_changed |= update_dependency(ctx, src_path)

  if is_changed: # must rebuild product.
    actual_src_path = actual_path_for_target(src_path) # source might itself be a product.
    has_product = build_product(ctx.info, target_path, actual_src_path, actual_path, use_std_out)
    if has_product:
      size, mtime = file_size_and_mtime(actual_path)
      file_hash = hash_for_path(actual_path)
      is_changed = (size != old.size or file_hash != old.hash)
      if not is_changed:
        noteF(target_path, 'product did not change (same size and hash).')
    else:
      size, mtime, file_hash = None, None, None
  else:
    file_hash = old.hash

  return update_deps_and_info(ctx, target_path, actual_path, is_changed, size, mtime, file_hash, src_path, old.deps)


def update_non_product(ctx: Ctx, target_path: str, is_changed: bool, size, mtime, old) -> bool:
  file_hash = hash_for_path(target_path) # must be calculated in all cases.
  if not is_changed: # all we know is that it exists and status as a source has not changed.
    is_changed = (size != old.size or file_hash != old.hash)
    if is_changed: # this is more interesting; report.
      noteF(target_path, 'source changed.')

  return update_deps_and_info(ctx, target_path, target_path, is_changed, size, mtime, file_hash, None, old.deps)


def update_deps_and_info(ctx, target_path: str, actual_path: str, is_changed, size, mtime, file_hash, src_path, old_deps) -> bool:
  if is_changed:
    deps = calc_dependencies(actual_path, ctx.dir_names)
  else:
    deps = old_deps
  for dep in deps:
    is_changed |= update_dependency(ctx, dep)

  ctx.statuses[target_path] = is_changed # replace sentinal with final value.
  info = TargetInfo(size, mtime, file_hash, src_path, deps)
  ctx.dbgF(target_path, 'updated info:\n  {}', info)
  ctx.info[target_path] = info
  # writing the entire dict at every step will not scale well;
  # at that point we should probably move to sqlite or similar anyway.
  save_info(ctx.info)
  return is_changed


def main():
  arg_parser = ArgumentParser(description='muck around with dependencies.')
  arg_parser.add_argument('targets', nargs='*', default=['index.html'], help='target file names.')
  arg_parser.add_argument('-dbg', action='store_true')
  args = arg_parser.parse_args()

  if args.dbg:
    def dbgF(path, fmt, *items):
      errF('muck dbg: {}: ' + fmt, path, *items)
  else:
    def dbgF(path, fmt, *items): pass

  command_needs_ctx, command_fn = commands.get(args.targets[0], (None, None))

  if command_fn and not command_needs_ctx:
    return command_fn(args.targets[1:])

  make_dirs(build_dir) # required for load_info.

  ctx = Ctx(info=load_info(), statuses={}, dir_names={}, dbgF=dbgF)

  if command_fn:
    assert command_needs_ctx
    command_fn(ctx, args.targets[1:])
  else: # no command; default behavior is to update each specified target.
    for target in args.targets:
      update_dependency(ctx, target, force=True)


if __name__ == '__main__':
  main()

