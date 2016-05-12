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

from bs4 import BeautifulSoup
from pithy import errFL
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

def source_html(path):
  'source handler for html.'
  with open(path) as f:
    return BeautifulSoup(f, 'html.parser')

def source_json(path):
  'source handler for json.'
  with open(path) as f:
    return json.load(f)

source_dispatch = {
  '.csv': agate.Table.from_csv,
  '.html': source_html,
  '.json': source_json,
}


def source(target_path, ext=None):
  'Muck API to open a dependency such that Muck can analyze dependencies statically.'
  # TODO: optional open_fn argument.
  path = actual_path_for_target(target_path)
  if ext is None:
    ext = path_ext(path)
  fn = source_dispatch.get(ext, open) # default to regular file open.
  try:
    return fn(path)
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
  errFL('fetch: {}', product_path)
  if not path_exists(product_path): 
    try:
      r = requests.get(url, timeout=timeout, headers=headers)
    except Exception as e:
      raise HTTPError('fetch failed with exception: {}'.format(e)) from e
    if r.status_code != expected_status_code:
      raise HTTPError('fetch failed with HTTP code: {}'.format(r.status_code)) from e
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
    use_std_out = True
    src_stem = prod_name
  else: # fall back to sources that do not indicate output extension.
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

def load_info():
  try:
    with open(info_path) as f:
      return json.load(f)
  except FileNotFoundError:
    return {}
  except json.JSONDecodeError as e:
    warnF(info_path, 'JSON decode failed; ignoring build info cache ({}).', e)
    return {}


def save_info(info_dict):
  with open(info_path, 'w') as f:
    json.dump(info_dict, f, indent=2)


dbg = False

def dbgF(path, fmt, *items):
  if dbg:
    errF('muck dbg: {}: ', path)
    errFL(fmt, * items)

def noteF(path, fmt, *items):
  errF('muck note: {}: ', path)
  errFL(fmt, *items)

def warnF(path, fmt, *items):
  errF('muck WARNING: {}: ', path)
  errFL(fmt, *items)

def muck_failF(path, fmt, *items):
  errF('muck error: {}: ', path)
  failF(fmt, *items)


def parse_patch_first_line(patch_path, patch_file=None, cmd=''):
  'returns (is_empty, original_path, product_path).'
  if patch_file is None:
    patch_file = open(patch_path)
  line = patch_file.readline()
  patch_file.close()
  words = line.split()
  if len(words) != 4 or words[0] != 'diff' or (words[1] not in ('--git', '--muck')):
    name = ' {} '.format(cmd) if cmd else ''
    failF('''\
muck {} error: {}: first line of patch file is invalid;
  expected: 'diff (--git|--muck) [original_path] [product_path]\\n'
  actual: {!r}''', name, patch_path, line)
  return ((words[1] == '--muck'), words[2], words[3])


def patch_dependencies(src_path, src_file):
  is_empty, orig_path, _ = parse_patch_first_line(src_path, src_file)
  dep = orig_path[(len(build_dir) + 1):] if is_product_path(orig_path) else orig_path
  return [dep]


def py_dependencies(src_path, src_file):
  'Calculate dependencies of a python3 source file.'
  src_text = src_file.read()
  tree = ast.parse(src_text, src_path)
  for node in ast.walk(tree):
    if not isinstance(node, ast.Call): continue
    func = node.func
    if not isinstance(func, ast.Attribute): continue
    if not isinstance(func.value, ast.Name): continue
    # TODO: dispatch to handlers for all known functions.
    # add handler for source_url;
    # this should check that repeated urls and targets are consistent across entire project.
    if (func.value.id, func.attr) != ('muck', 'source'): continue
    if len(node.args) != 1 or not isinstance(node.args[0], ast.Str):
      muck_failF('{}:{}:{}: muck.source argument must be a single string literal.',
        src_path, node.lineno, node.col_offset)
    yield node.args[0].s


dependency_fns = {
  '.patch' : patch_dependencies,
  '.py' : py_dependencies,
  '.wu' : writeup_dependencies,
}

build_tools = {
  '.patch' : ['muck', 'apply'],
  '.py' : ['python3'],
  '.wu' : ['writeup']
}

def calc_dependencies(path):
  ext = path_ext(path)
  dep_fn = dependency_fns.get(ext)
  with open(path) as f:
    return sorted(dep_fn(path, f)) if dep_fn else []


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

def muck_apply(args):
  if len(args) != 2:
    failF('muck apply error: apply command takes two arguments: [patch_path] [product_path]')
  patch_path, prod_path = args

  def _failF(fmt, *items):
    errF('muck apply error: {}: ', patch_path)
    failF(fmt, *items)

  if path_ext(patch_path) != '.patch':
    _failF('argument does not specify a .patch file')
  is_empty, orig_path, _ = parse_patch_first_line(patch_path, cmd='apply')

  if is_empty: # patch command would fail, calling the patch garbage.
      copy_file(orig_path, prod_path)
  else:
    cmd = ['patch', '-p0', '--input=' + patch_path, '--output=' + prod_path]
    code = runC(cmd)
    if code != 0:
      _failF('patch command failed: {}', cmd)


def muck_clean(ctx, args):
  if not args:
    failF('muck clean error: clean command takes specific target arguments; use clean-all to remove all products.')
  info_dict = ctx[0]
  for arg in args:
    try:
      info = info_dict[arg]
    except KeyError:
      errFL('muck clean note: {}: skipping unknown target.', arg)
      continue
    prod_path = product_path_for_target(arg)
    remove_file_if_exists(prod_path)
    del info_dict[arg]


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
    and then creates an empty [target].patch.
  
  muck patch [target.patch]
    update the patch file with the diff of the previously specified original and target.
''')

  if len(args) == 2: # create new patch.
    assert len(args) == 2
    orig_target_path, target_path = args
    patch_path = target_path + '.patch'
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
    if path_ext(patch_path) != '.patch':
      failF('muck patch error: argument does not specify a .patch file: {!r}', patch_path)
    is_empty, orig_path, prod_path = parse_patch_first_line(patch_path, cmd='patch')

  # update patch (both cases).
  cmd = ['git', 'diff', '--patch', '--histogram', '--exit-code',
    '--no-index', '--no-prefix', '--no-color', '--no-renames',
    orig_path, prod_path]
  with open(patch_path, 'wb') as f:
    code = runC(cmd, out=f)
    if code == 0: # files are identical and nothing was output; need to write a no-op patch.
      # the gnu patch tool does not like empty patches,
      # so we are obliged to create our own format variant in order to specify the dependency.
      # we follow the pattern established by git with 'diff --git {orig} {prod}'.
      empty_patch = 'diff --muck {} {}\n'.format(orig_path, prod_path)
      patch_bytes = empty_patch.encode()
      f.write(patch_bytes)


commands = {
  # values are (needs_ctx, fn).
  'apply'     : (False, muck_apply),
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


def build_product(info_dict: dict, target_path: str, src_path: str, prod_path: str, use_std_out: bool):
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
  info_dict.pop(target_path, None) # delete metadata along with file.
  remove_file_if_exists(prod_path)
  remove_file_if_exists(prod_path_out)
  remove_file_if_exists(prod_path_tmp)
  # TODO: if not use_std_out, then maybe we should remove all products with matching stem?
  prod_dir = path_dir(prod_path)
  make_dirs(prod_dir)
  cmd = build_tool + [src_path, prod_path_tmp]
  noteF(target_path, 'building: `{}`', ' '.join(cmd))
  with (open(prod_path_out, 'wb') if use_std_out else None) as out_file:
    time_start = time.time()
    code = runC(cmd, out=out_file)
    time_end = time.time()
  if code != 0:
    muck_failF(target_path, 'build failed with code {}', code)
  if use_std_out:
    if path_exists(prod_path_tmp):
      noteF(target_path, 'source produced product file: {}', prod_path_tmp)
      move_file(prod_path_tmp, prod_path)
      if file_size(prod_path_out) == 0:
        remove_file(prod_path_out)
    else:
      noteF(target_path, 'source produced std output.')
      move_file(prod_path_out, prod_path)
  else:
    if not path_exists(prod_path_tmp):
      muck_failF(target_path, 'build failed to produce product: {}', prod_path_tmp)
    move_file(prod_path_tmp, prod_path)
  noteF(target_path, 'finished: {:0.2f} seconds', time_end - time_start)


def update_dependency(ctx: tuple, target_path: str, force=False):
  '''
  returns is_changed.
  ctx is a triple of (info_dict: dict, status_dict: dict, dir_names_cache: dict).
  '''
  info_dict, status_dict, dir_names_cache = ctx

  if target_path in reserved_names:
    muck_failF(target_path, 'target name is reserved; please rename the target.')
  if path_ext(target_path) in reserved_exts:
    muck_failF(target_path, 'target name has reserved extension; please rename the target.')

  try: # if in status_dict, this path has already been visited on this run.
    status = status_dict[target_path]
    if status is None: # recursion sentinal.
      muck_failF(target_path, 'target has circular dependency.')
    return status
  except KeyError: pass

  dbgF(target_path, 'update')

  status_dict[target_path] = None # recursion sentinal is replaced before return.
  
  is_product = not path_exists(target_path)
  actual_path = actual_path_for_target(target_path)

  try: # if in info_dict, cached info may be reusable.
    old_info = info_dict[target_path]
  except KeyError: # no previous record.
    dbgF(target_path, 'no cached info')
    old_hash = None
    old_src_path = None
    old_deps = []
    is_stale = True
  else: # have previous record. must check that it is not stale.
    dbgF(target_path, 'cached info: {}', old_info)
    old_hash = old_info[0]
    old_src_path = old_info[1]
    old_deps = old_info[2:]
    is_stale = False
    old_is_product = bool(old_src_path)
    if old_is_product != is_product: # nature of the target changed.
      is_stale = True
      noteF(target_path, 'target is {} a product', 'now' if is_product else 'no longer')
    elif not path_exists(actual_path): # file was deleted.
      is_stale = True
      noteF(target_path, 'old product was deleted: {}', actual_path)

  src_path = None
  file_hash = None

  if is_product:
    src_path, use_std_out = source_for_target(target_path, dir_names_cache)
    deps_path = src_path
    if old_src_path != src_path:
      is_stale = True
      if old_src_path:
        noteF(target_path, 'source path of target product changed')
        noteF(target_path, '  was: {}', old_src_path)
        noteF(target_path, '  now: {}', src_path)
    is_src_changed = update_dependency(ctx, src_path)
    dbgF(target_path, 'source changed: {}', is_src_changed)
    is_stale = is_stale or is_src_changed
    if not is_stale: # only calculate hash of existing product if we might still reuse it.
      file_hash = hash_for_path(actual_path)
      is_stale = (file_hash != old_hash)
      if is_stale:
        warnF(target_path, 'product hash changed; product may have been accidentally modified.')

  else: # non-product source.
    deps_path = actual_path
    file_hash = hash_for_path(actual_path)
    is_stale_hash = (file_hash != old_hash)
    dbgF(target_path, 'stale source hash: {}', is_stale_hash)
    is_stale = is_stale or is_stale_hash

  if is_stale:
    deps = calc_dependencies(deps_path)
  else:
    deps = old_deps
  for dep in deps:
    is_dep_stale = update_dependency(ctx, dep)
    is_stale = is_stale or is_dep_stale

  if is_product and (force or is_stale): # must rebuild product.
    # the source of this product might itself be a product.
    actual_src_path = actual_path_for_target(src_path)
    build_product(info_dict, target_path, actual_src_path, actual_path, use_std_out)
    file_hash = hash_for_path(actual_path)

  status_dict[target_path] = is_stale # replace sentinal with final is_changed value.
  info_dict[target_path] = [file_hash or old_hash, src_path] + deps
  #if is_stale: noteF(target_path, 'updated')
  return is_stale


def main():
  global dbg
  arg_parser = argparse.ArgumentParser(description='muck around with dependencies.')
  arg_parser.add_argument('targets', nargs='*', default=['index.html'], help='target file names.')
  arg_parser.add_argument('-dbg', action='store_true')
  args = arg_parser.parse_args()
  dbg = args.dbg

  command_needs_ctx, command_fn = commands.get(args.targets[0], (None, None))

  if command_fn and not command_needs_ctx:
    return command_fn(args.targets[1:])

  make_dirs(build_dir) # required for load_info.

  info_dict = load_info()
  status_dict = {} # target_path: str => is_changed: bool | None (the recursion sentinal).
  dir_names_cache = {} # dir_path: str => names: [str].
  ctx = (info_dict, status_dict, dir_names_cache)

  try:
    if command_fn:
      assert command_needs_ctx
      command_fn(ctx, args.targets[1:])
    else: # no command; default behavior is to update each specified target.
      for target in args.targets:
        update_dependency(ctx, target, force=True)
  except SystemExit:
    save_info(info_dict)
    raise
  else:
    save_info(info_dict)


if __name__ == '__main__':
  main()
  
