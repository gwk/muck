#!/usr/bin/env python3
# Dedicated to the public domain under CC0: https://creativecommons.org/publicdomain/zero/1.0/.

import argparse
import ast
import base64
import copy
import hashlib
import json
import os
import re
import sys
import string as _string
import sys

import agate
from bs4 import BeautifulSoup
import requests

from writeup.writeup import writeup_dependencies

from common.fs import *
from common.io import *
from common.subproc import runC


assert(sys.version_info.major == 3) # python 2 is not supported.

# muck libary functions.

build_dir = '_build'

def product_path_for_target(target_path):
  return path_join(build_dir, target_path)


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


def source(target_path):
  'Muck API to open a dependency such that Muck can analyze dependencies statically.'
  # TODO: optional open_fn argument.
  path = target_path if path_exists(target_path) else product_path_for_target(target_path)
  ext = path_ext(path)
  fn = source_dispatch.get(ext, open) # default to regular file open.
  try:
    return fn(path)
  except FileNotFoundError:
    logFL('muck.source cannot open path: {}', path)
    if path != target_path:
      logFL('note: nor does a file exist at source path: {}', target_path)
    raise


class MuckHTTPError(Exception):
  def __init__(self, message, request):
    super().__init__(message)
    self.request = request

def source_url(url, target, expected_status_code=200):
  is_cached = (target is not None)
  if not is_cached:
    # implementing uncached requests efficiently requires new versions of the source functions;
    # these will take a text argument instead of a path argument.
    # alternatively, the source functions could be reimplemented to take text strings,
    # and muck would do the open and read.
    raise ValueError('source_url does not yet support uncached requests.')
  path = product_path_for_target(target)
  if not path_exists(path): 
    r = requests.get(url)
    if r.status_code != expected_status_code:
      raise MuckHTTPError('source_url failed with HTTP code: {}'.format(r.status_code), r)
    with open(path, 'w') as f:
      f.write(r.text)
  return source(path)


# module exports. when imported, muck provides functions that make data dependencies explicit.
__ALL__ = [
  source,
  source_url,
]  


# main executable.
if __name__ == '__main__':
  
  muck_dir = abs_path(path_dir(sys.argv[0])) # the directory where this program lives.
  writeup_path = path_join(muck_dir, 'writeup/writeup.py')
  fetch_url_path = path_join(muck_dir, 'fetch-url.py') # TODO: remove.

  env = copy.copy(os.environ)
  pypath = list(filter(None, env.get('PYTHONPATH', '').split(':')))
  env['PYTHONPATH'] = ':'.join([muck_dir] + pypath)


  info_name = '_muck_info.json'
  info_path = path_join(build_dir, info_name)
  
  def clean_all():
    remove_dir_contents(build_dir)

  commands = {
    'clean' : clean_all
  }

  reserved_names = {
    build_dir,
    info_name,
  }

  reserved_names.update(commands)

  reserved_exts = {
    '.tmp',
  }

  arg_parser = argparse.ArgumentParser(description='muck around with dependencies.')
  arg_parser.add_argument('targets', nargs='*', default=['index.html'], help='target file names.')
  args = arg_parser.parse_args()

  # must run commands before load_info, so that clean removes stale info first.
  for command in args.targets:
    try:
      fn = commands[command]
    except KeyError: continue
    fn()

  # info dictionaries.
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

  info_dict = load_info()
  status_dict = {} # key: target_path; val: is_changed: bool, or None as recursion sentinal.

  def save_info():
    with open(info_path, 'w') as f:
      json.dump(info_dict, f, indent=2)

  def finish(code=0):
    save_info()
    sys.exit(code)

  def infoF(path, fmt, *items):
    return
    logF('muck info: {}: ', path)
    logFL(fmt, * items)

  def noteF(path, fmt, *items):
    logF('muck note: {}: ', path)
    logFL(fmt, *items)

  def warnF(path, fmt, *items):
    logF('muck WARNING: {}: ', path)
    logFL(fmt, *items)

  def failF(path, fmt, *items):
    logF('muck error: {}: ', path)
    logFL(fmt, *items)
    finish(1)

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
      # add handler for source_url; this should check that repeated urls and targets are consistent across entire project.
      if func.value.id != 'muck' or func.attr != 'source': continue
      if len(node.args) != 1 or not isinstance(node.args[0], ast.Str):
        failF('{}:{}:{}: muck.source argument must be a single string literal.', src_path, node.lineno, node.col_offset)
      yield node.args[0].s

  dependency_fns = {
    '.py' : py_dependencies,
    '.wu' : writeup_dependencies,
  }

  build_tools = {
    '.py' : 'python3',
    '.wu' : writeup_path,
    '.url' : fetch_url_path, # TODO: remove.
  }

  def calc_dependencies(path):
    ext = path_ext(path)
    dep_fn = dependency_fns.get(ext)
    return sorted(dep_fn(path, open(path))) if dep_fn else []

  def hash_for_path(path):
    '''
    return a hash string for the contents of the file at the given path.
    '''
    try:
      f = open(path, 'rb')
    except IsADirectoryError:
      failF(path, 'expected a file but found a directory')
    h = hashlib.sha256()
    chunk_size = 1 << 12
    while True:
      chunk = f.read(chunk_size)
      if not chunk: break
      h.update(chunk)
    d = h.digest()
    return base64.urlsafe_b64encode(d).decode()

  _dir_names = {}
  def list_dir_filtered(src_dir):
    'caches and returns the list of names in a source directory that might be source files.'
    try:
      return _dir_names[src_dir]
    except KeyError: pass
    names = [n for n in list_dir(src_dir) if n not in reserved_names and not n.startswith('.')]
    _dir_names[dir] = names
    return names
  
  def filter_source_names(names, prod_name):
    l = len(prod_name)
    for name in names:
      if name.startswith(prod_name) and len(name) > l and name[l] == '.':
        yield name

  def immediate_source_name(name, src_stem):
    i = name.find('.', len(src_stem) + 2) # skip the stem and the first dot.
    if i == -1: return name
    return name[:i] # omit all but the first extension.

  def source_for_target(target_path):
    '''
    assumes target_path does not exist.
    returns (source_path: string, use_std_out: bool).
    '''
    src_dir, prod_name = split_dir_name(target_path)
    prod_stem, prod_ext = split_stem_ext(prod_name)
    src_dir_names = list_dir_filtered(src_dir or '.')
    # if a source file stem contains the complete target name, including extension, prefer that.
    src_names = list(filter_source_names(src_dir_names, prod_name))
    if src_names:
      use_std_out = True
      src_stem = prod_name
    else: # fall back to sources that do not indicate output extension.
      src_names = list(filter_source_names(src_dir_names, prod_stem))
      use_std_out = False
      src_stem = prod_stem
    if len(src_names) != 1:
      msg = 'multiple source candidates: {}'.format(src_names) if src_names else 'no source candidates matching `{}`'.format(prod_stem)
      failF(target_path, '{}', msg)
    ultimate_src_name = src_names[0]
    src_name = immediate_source_name(ultimate_src_name, src_stem)
    src_path = path_join(src_dir, src_name)
    assert src_path != target_path
    return (src_path, use_std_out)

  def build_product(target_path: str, src_path: str, prod_path: str, use_std_out: bool):
    '''
    build a product from a source.
    ''' 
    src_ext = path_ext(src_path)
    try:
      build_tool = build_tools[src_ext]
    except KeyError:
      # TODO: fall back to generic .deps file.
      failF(target_path, 'unsupported source file extension: `{}`', src_ext)
    prod_path_tmp = prod_path + '.tmp'
    remove_file_if_exists(prod_path)
    remove_file_if_exists(prod_path_tmp)
    prod_dir = path_dir(prod_path)
    make_dirs(prod_dir)
    cmd = [build_tool, src_path]
    noteF(target_path, 'building: `{}`', ' '.join(cmd))
    out_file = open(prod_path_tmp, 'wb') if use_std_out else None
    code = runC(cmd, cwd=None, stdin=None, out=out_file, err=None, env=env, exp=None)
    if code != 0:
      failF(target_path, 'build failed with code {}', code)
    if use_std_out:
      move_file(prod_path_tmp, prod_path)
    else:
      if not path_exists(prod_path):
        failF(target_path, 'build failed to produce product: {}', prod_path)


  def update_dependency(target_path):
    '''
    returns is_changed.
    '''

    if target_path in reserved_names:
      failF(target_path, 'target name is reserved; please rename the target.')
    if path_ext(target_path) in reserved_exts:
      failF(target_path, 'target name has reserved extension; please rename the target.')

    try: # if in status_dict, this path has already been visited on this run.
      status = status_dict[target_path]
      if status is None: # recursion sentinal.
        failF(target_path, 'target has recursive dependency: {}')
      return status
    except KeyError: pass

    infoF(target_path, 'update')

    status_dict[target_path] = None # recursion sentinal is replaced before return.
    
    is_product = not path_exists(target_path)
    actual_path = product_path_for_target(target_path) if is_product else target_path

    try: # if in info_dict, cached info may be reusable.
      old_info = info_dict[target_path]
    except KeyError: # no previous record.
      infoF(target_path, 'no cached info')
      old_hash = None
      old_src_path = None
      old_deps = []
      is_stale = True
    else: # have previous record. must check that it is not stale.
      infoF(target_path, 'cached info: {}', old_info)
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
      src_path, use_std_out = source_for_target(target_path)
      if old_src_path != src_path:
        is_stale = True
        if old_src_path:
          noteF(target_path, 'source path of target product changed')
          noteF(target_path, '  was: {}', old_src_path)
          noteF(target_path, '  now: {}', src_path)
      is_src_changed = update_dependency(src_path)
      infoF(target_path, 'source changed: {}', is_src_changed)
      is_stale = is_stale or is_src_changed
      if not is_stale: # only calculate hash of existing product if we might still reuse it.
        file_hash = hash_for_path(actual_path)
        is_stale = (file_hash != old_hash)
        if is_stale:
          warnF(target_path, 'product hash changed; product may have been accidentally modified.')

    else: # non-product source.
      file_hash = hash_for_path(actual_path)
      is_stale_hash = (file_hash != old_hash)
      infoF(target_path, 'stale source hash: {}', is_stale_hash)
      is_stale = is_stale or is_stale_hash

    if is_stale:
      deps = calc_dependencies(actual_path)
    else:
      deps = old_deps
    for dep in deps:
      is_dep_stale = update_dependency(dep)
      is_stale = is_stale or is_dep_stale

    if is_stale and is_product: # must rebuild product.
      # the source of this product might itself be a product.
      # if so, use its actual (product) path for the build step.
      is_src_a_product = not path_exists(src_path)
      actual_src_path = product_path_for_target(src_path) if is_src_a_product else src_path
      build_product(target_path, actual_src_path, actual_path, use_std_out)
      file_hash = hash_for_path(actual_path)

    status_dict[target_path] = is_stale # replace sentinal with final is_changed value.
    info_dict[target_path] = [file_hash or old_hash, src_path] + deps
    if is_stale:
      noteF(target_path, 'updated')
    return is_stale

  for target in args.targets:
    if target in commands: continue
    update_dependency(target)

  finish()
