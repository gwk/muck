#!/usr/bin/env python3
# Dedicated to the public domain under CC0: https://creativecommons.org/publicdomain/zero/1.0/.

import argparse
import ast
import base64
import copy
import hashlib
import json
import os
import random
import re
import sys
import time
import urllib.parse

import agate
import requests
import pithy.meta as meta

from http import HTTPStatus
from itertools import repeat
from bs4 import BeautifulSoup
from pat import pat_dependencies
from writeup import writeup_dependencies
from pithy import *


assert(sys.version_info.major == 3) # python 2 is not supported.


# muck libary functions.

build_dir = '_build'

def is_product_path(path):
  return path == build_dir or path.startswith(build_dir + '/')

def product_path_for_target(target_path):
  if is_product_path(target_path):
    raise ValueError('provided target path is prefixed with build dir: {}'.format(target_path))
  return path_join(build_dir, target_path)

def actual_path_for_target(target_path):
  'returns the target_path, if it exists, or else the corresponding product path.'
  if path_exists(target_path):
    return target_path
  return product_path_for_target(target_path)


def _source_csv(path):
  'source handler for csv.'
  return agate.Table.from_csv(path)

def _source_html(path):
  'source handler for html.'
  with open(path) as f:
    return BeautifulSoup(f, 'html.parser')

def _source_json(path):
  'source handler for json.'
  with open(path) as f:
    return json.load(f)

def _source_default(path):
  return open(path)

_source_dispatch = meta.dispatcher_for_names(prefix='_source_', default='default')

def source(target_path, ext=None):
  '''
  Open a dependency and parse it based on its file extension.
  Muck's static analysis looks specifically for this function to infer dependencies;
  the target_path argument must be a string literal.
  '''
  # TODO: optional open_fn argument.
  path = actual_path_for_target(target_path)
  if ext is None:
    ext = path_ext(path)
  try:
    return _source_dispatch(ext.lstrip('.'), path)
  except FileNotFoundError:
    errFL('muck.source cannot open path: {}', path)
    if path != target_path:
      errFL('note: nor does a file exist at source path: {}', target_path)
    raise


class HTTPError(Exception): pass


def target_path_from_url(url):
  '''
  produce a local target path from a url.
  '''
  parts = urllib.parse.urlsplit(url) # returns five-element sequence.
  name = plus_encode(''.join((parts.path, parts.query, parts.fragment)))
  return path_join(parts.scheme, plus_encode(parts.netloc), name)


def _fetch(url, timeout, headers, expected_status_code):
  '''
  wrap the call to get with try/except that flattens any exception trace into an HTTPError.
  without this the backtrace due to a network failure is massive, involves multiple exceptions,
  and is mostly irrelevant to the caller.
  '''
  try:
    msg = None
    r = requests.get(url, timeout=timeout, headers=headers)
  except Exception as e:
    msg = 'fetch failed with exception: {}: {}'.format(
      type(e).__name__, ', '.join(str(a) for a in e.args))
  else:
    if r.status_code != expected_status_code:
      s = HTTPStatus(r.status_code)
      msg = 'fetch failed with HTTP code: {}: {}; {}.'.format(s.code, s.phrase, s.description)
  if msg is not None:
    raise HTTPError(msg)
  return r


def fetch(url, path, ext='', expected_status_code=200, headers={}, timeout=4, delay=0, delay_range=0):
  'Muck API to fetch a url.'
  # seems weird for the api to allow either target or product paths,
  # but it makes sense to be more user-friendly here because they are essentially unambiguous.
  # muck will pass the product path to tools,
  # but users will prefer to type plain target paths into their code.
  if is_product_path(path):
    product_path = path
  else:
    product_path = product_path_for_target(path)
  errFL('fetch: {}', url)
  if not path_exists(product_path):
    r = _fetch(url, timeout, headers, expected_status_code)
    make_dirs(path_dir(product_path))
    with open(product_path, 'wb') as f:
      f.write(r.content)
    sleep_min = delay - delay_range * 0.5
    sleep_max = delay + delay_range * 0.5
    sleep_time = random.uniform(sleep_min, sleep_max)
    if sleep_time > 0:
      time.sleep(sleep_time)
  return product_path


def source_url(url, target_path=None, ext='', expected_status_code=200, headers={},
 timeout=4, delay=0, delay_range=0):
  # note: implementing uncached requests efficiently requires new versions of the source functions;
  # these will take a text argument instead of a path argument.
  # alternatively, the source functions could be reimplemented to take text strings,
  # or perhaps streams.
  # in the uncached case, muck would do the open and read.
  if target_path is None:
    target_path = target_path_from_url(url + ext)
  fetch(url, path=target_path, ext=ext, expected_status_code=expected_status_code,
    headers=headers, timeout=timeout, delay=delay, delay_range=delay_range)
  return source(target_path)


def list_dir_filtered(src_dir, cache=None):
  'caches and returns the list of names in a source directory that might be source files.'
  try:
    if cache is not None:
      return cache[src_dir]
  except KeyError: pass
  names = [n for n in list_dir(src_dir) if n not in reserved_names and not n.startswith('.')]
  if cache is not None:
    cache[dir] = names
  return names


ignored_exts = {
  '.err', '.iot', '.out', # iotest extensions.
}

def filter_source_names(names, prod_name):
  l = len(prod_name)
  for name in names:
    if name.startswith(prod_name) and len(name) > l and name[l] == '.' \
    and path_ext(name) not in ignored_exts:
      yield name


def immediate_source_name(name, src_stem):
  i = name.find('.', len(src_stem) + 2) # skip the stem and the first extension dot.
  if i == -1: return name
  return name[:i] # omit all extensions but the first.


def source_for_target(target_path, dir_names_cache=None):
  '''
  assumes target_path does not exist.
  returns (source_path: string, use_std_out: bool).
  '''
  src_dir, prod_name = split_dir_name(target_path)
  prod_stem, prod_ext = split_stem_ext(prod_name)
  src_dir_names = list_dir_filtered(src_dir or '.', cache=dir_names_cache)
  # if a source file stem contains the complete target name, including extension, prefer that.
  src_names = list(filter_source_names(src_dir_names, prod_name))
  if src_names:
    # only use stdout for targets with extensions;
    # extensionless targets are typically either phony or binary programs.
    use_std_out = bool(path_ext(prod_name))
    src_stem = prod_name
  else: # fall back to sources that do not indicate output extension.
    # TODO: decide if there is value to this feature; causes confusion when an extension is misspelled in a source file name.
    src_names = list(filter_source_names(src_dir_names, prod_stem))
    use_std_out = False
    src_stem = prod_stem
  if len(src_names) == 0:
    muck_failF(target_path, 'no source candidates matching `{}`'.format(src_stem))
  if len(src_names) != 1:
    muck_failF(target_path, 'multiple source candidates matching `{}`: {}'.format(src_stem, src_names))
  ultimate_src_name = src_names[0]
  src_name = immediate_source_name(ultimate_src_name, src_stem)
  src_path = path_join(src_dir, src_name)
  assert src_path != target_path
  return (src_path, use_std_out)


# module exports.
__all__ = [
  fetch,
  source,
  source_url,
  source_for_target,
]  


info_name = '_muck_info.json'
info_path = path_join(build_dir, info_name)

# info dictionary stores the persistent build information.
# key: target path (not product paths prefixed with build_dir).
# val: [file_hash, src_path, dependencies...]
# src_path may be None for non-product sources.
# each dependency is a target path.
# TODO: save info about muck version itself in the dict.

def load_info():
  try:
    with open(info_path) as f:
      return json.load(f)
  except FileNotFoundError:
    return {}
  except json.JSONDecodeError as e:
    warnF(info_path, 'JSON decode failed; ignoring build info cache ({}).', e)
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

def muck_failF(path, fmt, *items):
  errF('muck error: {}: ', path)
  failF(fmt, *items)


def py_dep_call(src_path, node):
  func = node.func
  if not isinstance(func, ast.Attribute): return
  if not isinstance(func.value, ast.Name): return
  # TODO: dispatch to handlers for all known functions.
  # add handler for source_url;
  # this should check that repeated (url, target) pairs are consistent across entire project.
  if (func.value.id, func.attr) != ('muck', 'source'): return None
  if len(node.args) != 1 or not isinstance(node.args[0], ast.Str):
    muck_failF('{}:{}:{}: muck.source argument must be a single string literal.',
      src_path, node.lineno, node.col_offset)
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
    dep_fn = dependency_fns.get(ext)
  except KeyError:
    return []
  with open(path) as f:
    return sorted(dep_fn(path, f, dir_names))


def hash_for_path(path):
  '''
  return a hash string for the contents of the file at the given path.
  '''
  try:
    f = open(path, 'rb')
  except IsADirectoryError:
    muck_failF(path, 'expected a file but found a directory')
  h = hashlib.sha256()
  chunk_size = 1 << 12
  while True:
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
  cmd = ['pat', 'diff', orig_path, prod_path]
  with open(patch_path, 'wb') as f:
    code = runC(cmd, out=f)

  if len(args) == 1: # updated existing patch.
    # need to remove or update the target info to avoid the 'did you mean to patch?' safeguard.
    # for now, just delete it to be safe; this makes the target looks stale.
    try:
      del ctx.info[target_path]
    except KeyError: pass


commands = {
  # values are (needs_ctx, fn).
  'clean'     : (True,  muck_clean),
  'clean-all' : (False, muck_clean_all),
  'patch'     : (True,  muck_patch),
}

reserved_names = {
  build_dir,
  info_name,
}.union(commands)

reserved_exts = {
  '.tmp',
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
  noteF(target_path, 'building: `{}`', ' '.join(cmd))
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
  size_suffix = '; {:0.2f} MB'.format(file_size(prod_path) / 1000000) if has_product else ''
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

  needs_update = force or not has_existing_actual

  try:
    old_info = ctx.info[target_path]
  except KeyError: # no previous record.
    ctx.dbgF(target_path, 'no cached info')
    old_size, old_mtime, old_hash, old_src_path = repeat(None, 4)
    old_deps = []
    has_old_info = False
    needs_update = True
  else: # have previous record. must check that it is not stale.
    old_size, old_mtime, old_hash, old_src_path = old_info[:4]
    old_deps = old_info[4:]
    has_old_info = True
    ctx.dbgF(target_path, 'cached size: {}; mtime: {}; hash: {}; src: {}; deps: {}',
      old_size, old_mtime, old_hash, old_src_path, old_deps)
    old_is_product = bool(old_src_path)
    if old_is_product != is_product: # nature of the target changed.
      needs_update = True
      noteF(target_path, 'target is {} a product', 'now' if is_product else 'no longer')
    elif not has_existing_actual: # file was deleted.
      assert is_product
      needs_update = True
      if target_ext: # definitely not a phony target, so show the message.
        noteF(target_path, 'old product was deleted: {}', actual_path)

  ctx.dbgF(target_path, 'is product: {}; has existing actual: {};  has old info: {}',
     is_product, has_existing_actual, has_old_info)

  file_hash = old_hash # will update with the new product later if necessary.
  src_path = None # filled in for product.

  if is_product:
    if has_existing_actual and has_old_info:
      # existing product should not have been modified since info was stored.
      act_hash = hash_for_path(actual_path)
      if size != old_size or act_hash != old_hash:
        ctx.dbgF(target_path, 'size: {} -> {}; hash: {} -> {}', old_size, file_size, old_hash, act_hash)
        muck_failF(target_path, 'existing product has changed; did you mean to update a patch?\n'
          '  please save your changes if necessary and then delete the modified file.')
    src_path, use_std_out = source_for_target(target_path, ctx.dir_names)
    if old_src_path != src_path:
      needs_update = True
      if old_src_path:
        noteF(target_path, 'source path of target product changed\n  was: {}\n  now: {}',
          old_src_path, src_path)
    is_src_changed = update_dependency(ctx, src_path)
    needs_update = needs_update or is_src_changed
    deps_path = src_path

  else: # non-product source.
    assert has_existing_actual
    file_hash = hash_for_path(actual_path)
    is_changed = size != old_size or file_hash != old_hash
    if is_changed:
      noteF(target_path, 'changed.')
    needs_update = needs_update or is_changed
    deps_path = actual_path

  if needs_update:
    deps = calc_dependencies(deps_path, ctx.dir_names)
  else:
    deps = old_deps
  for dep in deps:
    is_dep_stale = update_dependency(ctx, dep)
    needs_update = needs_update or is_dep_stale

  if is_product and needs_update: # must rebuild product.
    # the source of this product might itself be a product.
    actual_src_path = actual_path_for_target(src_path)
    has_product = build_product(ctx.info, target_path, actual_src_path, actual_path, use_std_out)
    if has_product:
      size, mtime = file_size_and_mtime(actual_path)
      file_hash = hash_for_path(actual_path)
      needs_update = (file_hash != old_hash) # result is unchanged.

  ctx.statuses[target_path] = needs_update # replace sentinal with final is_changed value.
  ctx.info[target_path] = [size, mtime, file_hash, src_path] + deps
  #if needs_update: noteF(target_path, 'updated')
  return needs_update


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
  
