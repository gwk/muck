# Dedicated to the public domain under CC0: https://creativecommons.org/publicdomain/zero/1.0/ by George King.

import os as _os
import os.path as _path


# paths.

def path_name(path): return _path.basename(path)

def path_common_prefix(*paths): return _path.commonprefix(paths)

def path_rel_to(base, path):
  if not path.startswith(base):
    raise ValueError('path expected to have prefix: {}; actual: {}'.format(base, path))
  return path[len(base):]

def path_dir(path): return _path.dirname(path)

def path_dir_or_dot(path): return path_dir(path) or '.'

def is_path_abs(path): return _path.isabs(path)

def path_join(*items): return _path.join(*items)

def norm_path(path): return _path.norm(path)

def split_dir_name(path): return _path.split(path)

def split_stem_ext(path): return _path.splitext(path)

def path_stem(path):
  'the path without the file extension.'
  return split_stem_ext(path)[0]

def path_ext(path):
  'the file extension of the path.'
  return split_stem_ext(path)[1]

def path_name_stem(path):
  'the file name without extension.'
  return path_stem(path_name(path))

def split_dir_stem_ext(path):
  '(dir, stem, ext) triple.'
  d, n = split_dir_name(path)
  s, e = split_stem_ext(n)
  return d, s, e



# file system.

def abs_path(path): return _path.abspath(path)

def path_exists(path): return _path.exists(path)

def expand_user(path): return _path.expanduser(path)

def is_dir(path): return _path.isdir(path)

def is_file(path): return _path.isfile(path)

def is_link(path): return _path.islink(path)

def is_mount(path): return _path.ismount(path)

def link_exists(path): return _path.lexists(path)

def list_dir(path): return _os.listdir(path)

def make_dir(path): return _os.mkdir(path)

def make_dirs(path, mode=0o777, exist_ok=True): return _os.makedirs(path, mode, exist_ok)

def remove_file(path): return _os.remove(path)

def remove_file_if_exists(path):
  if is_file(path):
    remove_file(path)

def remove_dir(path): return _os.rmdir(path)

def remove_dirs(path): return _os.removedirs(path)


def current_dir(): return abs_path('.')

def parent_dir(): return abs_path('..')

def time_access(path): return _os.stat(path).st_atime

def time_mod(path): return _os.stat(path).st_mtime

def time_meta_change(path): return _os.stat(path).st_ctime

def is_file_not_link(path): return is_file(path) and not is_link(path)

def is_dir_not_link(path): return is_dir(path) and not is_link(path)


def remove_dir_contents(path):
  if _path.islink(path): raiseS(OSError, 'remove_dir_contents received symlink:', path)
  l = _os.listdir(path)
  for n in l:
    p = _path.join(path, n)
    if _path.isdir(p):
      remove_dir_tree(p)
    else:
      _os.remove(p)


def remove_dir_tree(path):
  remove_dir_contents(path)
  _os.rmdir(path)


def move_file(path, dest, overwrite=False):
  if path_exists(dest) and not overwrite:
    raise OSError('destination path already exists: '.format(dest))
  _os.rename(path, dest)


def write_to_path(path, string):
  with open(path, 'w') as f:
    f.write(string)


def _walk_all_paths_rec(path_pairs, yield_files, yield_dirs, exts, hidden):
  'yield paths; dir path are distinguished by trailing slash.'
  for dir, name, in path_pairs:
    path = _path.join(dir, name)
    is_dir = _path.isdir(path)
    if not hidden and name.startswith('.') and name != '.':
      continue
    if is_dir:
      if yield_dirs:
        yield path + '/'
      subs = ((path, n) for n in _os.listdir(path))
      yield from _walk_all_paths_rec(subs, yield_files, yield_dirs, exts, hidden)
    else: # file.
      if yield_files and (exts is None or _path.splitext(name)[1] in exts):
        yield path


def walk_all_paths(*paths, make_abs=False, yield_files=True, yield_dirs=True, exts=None,
  hidden=False):
  '''
  generate file and/or dir paths,
  after optionally filtering by file extension and/or hidden names (leading dot).
  '''
  assert not isinstance(exts, str) # exts should be a sequence of strings.
  assert exts is None or all(e.startswith('.') for e in exts) # all extensions should begin with a dot.

  def norm_path(p):
    while p.endswith('/'):
      p = p[:-1]
    return _path.abspath(p) if make_abs else p

  norm_paths = sorted(norm_path(p) for p in paths)
  path_pairs = tuple(_path.split(p) for p in norm_paths)
  return _walk_all_paths_rec(path_pairs, yield_files, yield_dirs, exts, hidden)


def walk_all_files(*paths, make_abs=False, exts=None, hidden=False):
  return walk_all_paths(*paths, make_abs=make_abs, yield_files=True, yield_dirs=False,
    exts=exts, hidden=hidden)


def walk_all_dirs(*paths, make_abs=False, exts=None, hidden=False):
  return walk_all_paths(*paths, make_abs=make_abs, yield_files=False, yield_dirs=True,
    exts=exts, hidden=hidden)


