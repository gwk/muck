#!/usr/bin/env python3
# Dedicated to the public domain under CC0: https://creativecommons.org/publicdomain/zero/1.0/.

import sys
assert sys.version_info.major == 3 # python 2 is not supported.

import argparse
import ast
import base64
import hashlib
import json
import os
import shlex
import time

from pat import pat_dependencies
from writeup import writeup_dependencies
from pithy import *

from muck import actual_path_for_target, build_dir, ignored_exts, info_name, muck_failF, \
reserved_exts, product_path_for_target, reserved_names, source_for_target


TargetInfo = namedtuple('TargetInfo', 'size, mtime, hash, src_path deps')


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
  module_parts = module_name.split('.')
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


def tests_dependencies(src_path, src_file, dir_names):
  lines = (line.strip() for line in src_file)
  return [l for l in lines if l and not l.startswith('#')]


dependency_fns = {
  '.pat' : pat_dependencies,
  '.py' : py_dependencies,
  '.tests' : tests_dependencies,
  '.wu' : writeup_dependencies,
}

build_tools = {
  '.pat' : ['pat', 'apply'],
  '.py' : ['python3'],
  '.tests' : ['true'],
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
  h = hashlib.sha256()
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


def muck_clean_all(args):
  if args:
    failF('muck clean-all error: clean-all command no arguments; use clean to remove individual products.')
  remove_dir_contents(build_dir)


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
    assert len(args) == 2
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
    except KeyError: pass


commands = {
  # values are (needs_ctx, fn).
  'clean'     : (True,  muck_clean),
  'clean-all' : (False, muck_clean_all),
  'patch'     : (True,  muck_patch),
}


def build_product(info: dict, target_path: str, src_path: str, prod_path: str, use_std_out: bool):
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
  info.pop(target_path, None) # delete metadata along with file.
  remove_file_if_exists(prod_path)
  remove_file_if_exists(prod_path_out)
  remove_file_if_exists(prod_path_tmp)
  # TODO: if not use_std_out, then maybe we should remove all products with matching stem?
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
  if use_std_out:
    if path_exists(prod_path_tmp):
      noteF(target_path, 'process wrote product file directly.')
      move_file(prod_path_tmp, prod_path)
      if file_size(prod_path_out) == 0:
        remove_file(prod_path_out)
    else:
      noteF(target_path, 'process produced std output.')
      move_file(prod_path_out, prod_path)
  else: # not use_std_out.
    if path_exists(prod_path_tmp):
      move_file(prod_path_tmp, prod_path)
    elif path_ext(prod_path): # target is not bare (possibly phony) target.
      muck_failF(target_path, 'build failed to produce product: {}', prod_path_tmp)
    else:
      has_product = False
      noteF(target_path, 'no product.')
  size_suffix = ('; ' + format_byte_count_dec(file_size(prod_path))) if has_product else ''
  noteF(target_path, 'finished: {:0.2f} seconds{}.', time_end - time_start, size_suffix)
  return has_product


def file_size_and_mtime(path):
  stats = os.stat(path)
  return (stats.st_size, stats.st_mtime)


Ctx = namedtuple('Ctx', 'info statuses dir_names dbgF')
# statuses: target_path: str => is_changed: bool | None (the recursion sentinal).
# dir_names: dir_path: str => names: [str].


def update_dependency(ctx: Ctx, target_path: str, force=False):
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
  actual_path = actual_path_for_target(target_path)
  try:
    size, mtime = file_size_and_mtime(actual_path)
    has_existing_actual = True
  except FileNotFoundError:
    size = None
    mtime = None
    has_existing_actual = False

  is_changed = force or not has_existing_actual

  try:
    old = ctx.info[target_path]
  except KeyError: # no previous record.
    ctx.dbgF(target_path, 'no cached info')
    old = TargetInfo(None, None, None, None, [])
    has_old_info = False
    is_changed = True
  else: # have previous record. must check that it is not stale.
    has_old_info = True
    ctx.dbgF(target_path, 'old info:\n  {}', old)
    old_is_product = bool(old.src_path)
    if old_is_product != is_product: # nature of the target changed.
      is_changed = True
      noteF(target_path, 'target is {} a product', 'now' if is_product else 'no longer')
    elif not has_existing_actual: # file was deleted.
      assert is_product
      is_changed = True
      if target_ext: # definitely not a phony target, so show the message.
        noteF(target_path, 'old product was deleted: {}', actual_path)

  ctx.dbgF(target_path, 'is_changed: {}; is_product: {}; has_existing_actual: {};  has_old_info: {}',
     is_changed, is_product, has_existing_actual, has_old_info)

  src_path = None # filled in for product.

  if is_product:
    file_hash = old.hash # will update with the new product later if necessary.
    if has_existing_actual and has_old_info:
      # existing product should not have been modified since info was stored.
      # if the size changed then it was definitely modified.
      # otherwise, if the mtime is unchanged, assume that the file is ok, for speed.
      # if the mtime changed, check the hash;
      # the user might have made an accidental edit and then reverted it,
      # and we would rather compute the hash than report a false problem.
      if size != old.size or (mtime != old.mtime and hash_for_path(actual_path) != old.hash):
        ctx.dbgF(target_path, 'size: {} -> {}; mtime: {} -> {}', old.size, size, old.mtime, mtime)
        muck_failF(target_path, 'existing product has changed; did you mean to update a patch?\n'
          '  please save your changes if necessary and then delete the modified file.')
    src_path, use_std_out = source_for_target(target_path, ctx.dir_names)
    if old.src_path != src_path:
      is_changed = True
      if old.src_path:
        noteF(target_path, 'source path of target product changed\n  was: {}\n  now: {}',
          old.src_path, src_path)
    is_src_changed = update_dependency(ctx, src_path)
    is_changed |= is_src_changed
    deps_path = src_path

  else: # non-product source.
    assert has_existing_actual
    file_hash = hash_for_path(actual_path) # must be calculated in all cases.
    deps_path = actual_path
    if not is_changed: # at this point, this just means that existance and status as a source file has not changed.
      is_changed = (size != old.size or hash_for_path(actual_path) != old.hash)
      if is_changed:
        noteF(target_path, 'source changed.')

  if is_changed:
    deps = calc_dependencies(deps_path, ctx.dir_names)
  else:
    deps = old.deps
  for dep in deps:
    is_dep_stale = update_dependency(ctx, dep)
    is_changed |= is_dep_stale

  if is_product and is_changed: # must rebuild product.
    # the source of this product might itself be a product.
    actual_src_path = actual_path_for_target(src_path)
    has_product = build_product(ctx.info, target_path, actual_src_path, actual_path, use_std_out)
    if has_product:
      size, mtime = file_size_and_mtime(actual_path)
      file_hash = hash_for_path(actual_path)
      is_changed = (size != old.size or file_hash != old.hash)
      if not is_changed:
        noteF(target_path, 'product did not change (same size and hash).')
    else:
      if force:
        noteF(target_path, 'no product.')
        is_changed = True
        size, mtime, file_hash = None, None, None
      else:
        muck_failF(target_path, 'no product.')

  ctx.statuses[target_path] = is_changed # replace sentinal with final value.
  info = TargetInfo(size, mtime, file_hash, src_path, deps)
  ctx.info[target_path] = info
  ctx.dbgF(target_path, 'updated info:\n  {}', info)
  return is_changed


def main():
  arg_parser = argparse.ArgumentParser(description='muck around with dependencies.')
  arg_parser.add_argument('targets', nargs='*', default=['index.html'], help='target file names.')
  arg_parser.add_argument('-dbg', action='store_true')
  args = arg_parser.parse_args()

  if args.dbg:
    def dbgF(path, fmt, *items):
      errF('muck dbg: {}: ', path)
      errFL(fmt, *items)
  else:
    def dbgF(path, fmt, *items): pass

  command_needs_ctx, command_fn = commands.get(args.targets[0], (None, None))

  if command_fn and not command_needs_ctx:
    return command_fn(args.targets[1:])

  make_dirs(build_dir) # required for load_info.

  ctx = Ctx(info=load_info(), statuses={}, dir_names={}, dbgF=dbgF)

  try:
    if command_fn:
      assert command_needs_ctx
      command_fn(ctx, args.targets[1:])
    else: # no command; default behavior is to update each specified target.
      for target in args.targets:
        update_dependency(ctx, target, force=True)
  except SystemExit:
    save_info(ctx.info)
    raise
  else:
    save_info(ctx.info)


if __name__ == '__main__':
  main()
  
