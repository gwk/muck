# Dedicated to the public domain under CC0: https://creativecommons.org/publicdomain/zero/1.0/.
# muck libary functions.

import sys
assert sys.version_info.major == 3 # python 2 is not supported.

import random
import time

import requests
import pithy.meta as meta

from csv import reader as csv_reader
from http import HTTPStatus
from sys import argv
from pithy.path_encode import path_for_url
from pithy.io import errF, errFL, failF
from pithy.fs import make_dirs, path_dir, path_exists, path_ext, path_join, path_stem, split_dir_name, split_stem_ext, list_dir
from pithy.json_utils import load_json, load_jsonl, load_jsons
from pithy.transform import Transformer


# module exports.
__all__ = [
  'HTTPError',
  'add_loader',
  'fetch',
  'load',
  'load_url',
  'muck_failF',
  'open_dep',
  'source_for_target',
  'transform',
]


build_dir = '_build'
info_name = '_muck_info.json'

reserved_names = {
  'clean',
  'clean-all',
  'muck',
  'patch',
  build_dir,
  info_name,
}

reserved_exts = {
  '.tmp',
}

ignored_exts = {
  '.err', '.iot', '.out', # iotest extensions.
}


def muck_failF(path, fmt, *items):
  errF('muck error: {}: ', path)
  failF(fmt, *items)


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


def open_dep(target_path, binary=False, buffering=-1, encoding=None, errors=None, newline=None):
  '''
  Open a dependency for reading.

  Muck's static analysis looks specifically for this function to infer dependencies;
  `target_path` must be a string literal.
  '''
  path = actual_path_for_target(target_path)
  try:
    return open(path, mode=('rb' if binary else 'r'), buffering=buffering, encoding=encoding, errors=errors, newline=newline)
  except FileNotFoundError:
    errFL('muck.open_dep cannot open path: {}', path)
    if path != target_path:
      errFL('note: nor does a file exist at source path: {}', target_path)
    raise


_loaders = {
  '.csv' : (csv_reader, {'newlines': ''}),
  '.json' : (load_json, {}),
  '.jsonl' : (load_jsonl, {}),
  '.jsons' : (load_jsons, {}),
}

def add_loader(ext, fn, **open_args):
  if not ext.startswith('.'):
    raise ValueError("file extension does not start with '.': {!r}".format(ext))
  _loaders[ext] = (fn, open_args)


_unspecified = object()
def load(target_path, ext=_unspecified, **kwargs):
  '''
  Select an appropriate loader based on the file extension, or `ext` if specified.
  If not loader has been registered for the extension, or (`ext` is specified as `None`),
  then the file is opened with `kwargs` passed to `open_dep`.
  If a loader is found, then `open_dep` is called with the registered `open_args`,
  and the loader is called with `kwargs`.

  Muck's static analysis looks specifically for this function to infer dependencies;
  `target_path` must be a string literal.
  '''
  if ext is _unspecified:
    ext = path_ext(target_path)
  try: load_fn, open_args = _loaders[ext]
  except KeyError: pass
  else:
    file = open_dep(target_path, open_args)
    return load_fn(file, **kwargs)
  # default.
  return open_dep(target_path, **kwargs)


class HTTPError(Exception): pass


def _fetch(url, timeout, headers, expected_status_code):
  '''
  wrap the call to `get` with try/except that flattens any exception trace into an HTTPError.
  without this, a backtrace due to a network failure is massive, involves multiple exceptions,
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
      msg = 'fetch failed with HTTP code: {}: {}; {}.'.format(s.value, s.phrase, s.description)
  if msg is not None:
    raise HTTPError(msg)
  return r


def fetch(url, expected_status_code=200, headers={}, timeout=4, delay=0, delay_range=0):
  "Fetch the data at `url` and save it to a path in the '_fetch' directory derived from the URL."
  path = path_join('_fetch', path_for_url(url))
  if not path_exists(path):
    errFL('fetch: {}', url)
    r = _fetch(url, timeout, headers, expected_status_code)
    make_dirs(path_dir(path))
    with open(path, 'wb') as f:
      f.write(r.content)
    sleep_min = delay - delay_range * 0.5
    sleep_max = delay + delay_range * 0.5
    sleep_time = random.uniform(sleep_min, sleep_max)
    if sleep_time > 0:
      time.sleep(sleep_time)
  return path


def load_url(url, ext=_unspecified, expected_status_code=200, headers={}, timeout=4, delay=0, delay_range=0, **kwargs):
  'Fetch the data at `url` and then load using `muck.load`.'
  # note: implementing uncached requests efficiently requires new versions of the source functions;
  # these will take a text argument instead of a path argument.
  # alternatively, the source functions could be reimplemented to take text strings,
  # or perhaps streams.
  # in the uncached case, muck would do the open and read.
  path = fetch(url, expected_status_code=expected_status_code, headers=headers,
    timeout=timeout, delay=delay, delay_range=delay_range)
  return load(path, ext=ext, **kwargs)


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


def transform(target_path, ext=_unspecified, **kwargs):
  '''
  Open a dependency using muck.load and then transform it using pithy.Transformer.

  Additional keyword arguments are passed to the specific load function matching `ext`;
  see muck.load for details.

  Muck's static analysis looks specifically for this function to infer dependencies;
  `target_path` must be a string literal.
  '''
  seq = load(target_path, ext=ext, **kwargs)
  return Transformer(seq, log_stem=path_stem(argv[1]) + '.')
