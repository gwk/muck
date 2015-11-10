#!/usr/bin/env python3
# Dedicated to the public domain under CC0: https://creativecommons.org/publicdomain/zero/1.0/.

import argparse
import re
import sys
import os as _os
import os.path as _path
import string as _string


# from common.io.

def errF(fmt, *items):
  print(fmt.format(*items), end='', file=sys.stderr)

def errFL(fmt, *items):
  print(fmt.format(*items), file=sys.stderr)

def fail(fmt, *items):
  errFL(fmt, *items)
  sys.exit(1)

def check(cond, fmt, *items):
  if not cond:
    fail(fmt, *items)

# from common.fs.

def list_dir(path): return _os.listdir(path)

def make_dirs(path, mode=0o777, exist_ok=True): return _os.makedirs(path, mode, exist_ok)

def path_dir(path): return _path.dirname(path)

def path_dir_or_dot(path): return path_dir(path) or '.'

def path_name(path): return _path.basename(path)

def path_name_stem(path): return path_stem(path_name(path))

def path_stem(path): return split_ext(path)[0]

# muck.

# main executable.
if __name__ == '__main__':
  
  arg_parser = argparse.ArgumentParser(description='muck around with dependencies.')
  arg_parser.add_argument('targets', nargs='*', default=['index.html'], help='target file names.')
  args = arg_parser.parse_args()

  env = {
    'MUCK' : _path.dirname(sys.argv[0])
  }

  def expand(string):
    'test environment variable substitution; uses string template $ syntax.'
    t = _string.Template(string)
    return t.substitute(**env)

  source_tools = {
    '.wu' : expand('$MUCK/writeup/writeup.py')
  }

  def build(target_path):
    src_dir = path_dir_or_dot(target_path)
    stem = path_name_stem(target_path)
    src_dir_names = list_dir(src_dir or '.')
    src_names = []
    for n in src_dir_names:
      if path_stem(n) == stem:
        src_names.append(n)
    if len(src_names) != 1:
      msg = 'multiple source candidates: {}'.format(src_names) if src_names else 'no source file found matching "{}"'.format(stem)
      fail('error building target: {}; {}'.format(target_path, msg))
    src_name = src_names[0]
    src_path = '{}/{}'.format(src_dir, src_name)
    dst_dir = '_bld/{}'.format(src_dir)
    dst_path = '_bld/{}'.format(target_path)
    make_dirs(dst_dir)
    print('{}: {} -> {}'.format(target_path, src_path, dst_path))


  for target in args.targets:
    build(target)
