#!/usr/bin/env python3
# Dedicated to the public domain under CC0: https://creativecommons.org/publicdomain/zero/1.0/.

import argparse
import ast
import copy
import json
import os
import re
import sys
import string as _string
import sys

import agate
from bs4 import BeautifulSoup

from writeup.writeup import writeup_dependencies

from common.fs import *
from common.io import *
from common.subproc import runC


assert(sys.version_info.major == 3) # python 2 is not supported.

# muck.

def source_html(path):
  with open(path) as f:
    return BeautifulSoup(f, 'html.parser')

def source_json(path):
  with open(path) as f:
    return json.load(f)

source_dispatch = {
  '.csv': agate.Table.from_csv,
  '.html': source_html,
  '.json': source_json,
}

_source_dependency_map = None
def source(target_path):
  global _source_dependency_map
  if _source_dependency_map is None:
    arg_parser = argparse.ArgumentParser(description='uses generic muck dependency map parser.')
    arg_parser.add_argument('-dependency-map', nargs='?', default='', help='map dependency names to paths; format is "k1=v1,...,kN=vN.')
    args = arg_parser.parse_args()
    _source_dependency_map = {}
    for s in args.dependency_map.split(','):
      k, p, v = s.partition('=')
      if k in _source_dependency_map:
        failF('error: dependency map has duplicate key: {}', k)
      _source_dependency_map[k] = v
  path = _source_dependency_map.get(target_path, target_path)
  ext = path_ext(path)
  fn = source_dispatch.get(ext, open) # default to regular file open.
  return fn(path)

# module exports. when imported, muck provides functions that make data dependencies explicit.
__ALL__ = [
  source,
]  


def py_dependencies(src_path, src_file):
  src_text = src_file.read()
  tree = ast.parse(src_text, src_path)
  for node in ast.walk(tree):
    if not isinstance(node, ast.Call): continue
    func = node.func
    if not isinstance(func, ast.Attribute): continue
    if not isinstance(func.value, ast.Name): continue
    if func.value.id != 'muck' or func.attr != 'source': continue
    if len(node.args) != 1 or not isinstance(node.args[0], ast.Str):
      failF('muck error: {}:{}:{}: muck.source argument must be a single string literal.', src_path, node.lineno, node.col_offset)
    yield node.args[0].s

def fetch_url_dependencies(src_path, scr_file):
  return []


# main executable.
if __name__ == '__main__':
  
  arg_parser = argparse.ArgumentParser(description='muck around with dependencies.')
  arg_parser.add_argument('targets', nargs='*', default=['index.html'], help='target file names.')
  args = arg_parser.parse_args()

  muck_dir = abs_path(path_dir(sys.argv[0]))
  writeup_path = path_join(muck_dir, 'writeup/writeup.py')
  fetch_url_path = path_join(muck_dir, 'fetch-url.py')

  env = copy.copy(os.environ)
  pypath = list(filter(None, env.get('PYTHONPATH', '').split(':')))
  env['PYTHONPATH'] = ':'.join([muck_dir] + pypath)

  source_tools = {
    '.py' : (py_dependencies, 'python3'),
    '.wu' : (writeup_dependencies, writeup_path),
    '.url' : (fetch_url_dependencies, fetch_url_path),
  }

  def get_mtime(path):
    try:
      return os.path.getmtime(path)
    except FileNotFoundError:
      return 0.0

  def build(target_path):
    src_dir, dst_name = split_dir_name(target_path)
    stem, dst_ext = split_stem_ext(dst_name)
    src_dir_names = list_dir(src_dir or '.')
    # if a source file stem contains the complete target name, including extension, prefer that.
    src_names = [n for n in src_dir_names if path_stem(n) == dst_name]
    if src_names:
      use_std_out = True
    else: # fall back to sources that do not indicate output extension.
      use_std_out = False
      src_names = [n for n in src_dir_names if path_stem(n) == stem]
    if len(src_names) != 1:
      msg = 'multiple source candidates: {}'.format(src_names) if src_names else 'no source candidates matching `{}`'.format(stem)
      failF('muck error: target: {}; {}', target_path, msg)
    src_name = src_names[0]
    src_ext = path_ext(src_name)
    src_path = path_join(src_dir, src_name)
    if src_path == target_path: # target exists as-is; nothing to build.
      logFL('muck: found `{}`', src_path)
      return (src_path, get_mtime(src_path))
    dst_dir = path_join('_bld', src_dir)
    dst_path = path_join(dst_dir, dst_name)
    dst_path_tmp = dst_path + '.tmp'
    try:
      deps_fn, build_tool = source_tools[src_ext]
    except KeyError:
      failF('muck error: unsupported source file extension: `{}`', src_ext)
    # TODO: fall back to generic .deps file.
    deps = deps_fn(src_path, open(src_path)) if deps_fn else []
    dependency_map = {}
    src_mtime = get_mtime(src_path)
    dst_mtime = get_mtime(dst_path)
    is_fresh = (src_mtime < dst_mtime)
    # TODO: calculate all source dependencies.
    for dep in sorted(deps): # sort for build consistency.
      (dep_path, dep_mtime) = build(dep)
      dependency_map[dep] = dep_path
      is_fresh = is_fresh and dep_mtime < dst_mtime
    if is_fresh:
      logFL('muck: reusing `{}`', dst_path)
      return (dst_path, dst_mtime)
    remove_file_if_exists(dst_path)
    remove_file_if_exists(dst_path_tmp)
    dependency_map_arg = ','.join('{}={}'.format(*kv) for kv in sorted(dependency_map.items()))
    make_dirs(dst_dir)
    cmd = [build_tool, src_path, '-dependency-map', dependency_map_arg]
    logFL('muck: building `{}`: {}', target_path, ' '.join(cmd))
    out_file = open(dst_path_tmp, 'wb') if use_std_out else None
    code = runC(cmd, cwd=None, stdin=None, out=out_file, err=None, env=env, exp=None)
    if code != 0:
      failF('muck error: {}: exited with code {}', src_path, code)
    if use_std_out:
      move_file(dst_path_tmp, dst_path)
    else:
      if not path_exists(dst_path):
        failF('muck error: {}: failed to produce `{}`', src_path, dst_path)
    return (dst_path, get_mtime(dst_path))

  for target in args.targets:
    build(target)
