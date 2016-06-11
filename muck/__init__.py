# Dedicated to the public domain under CC0: https://creativecommons.org/publicdomain/zero/1.0/.
# muck libary functions.

import sys
assert sys.version_info.major == 3 # python 2 is not supported.

import random
import time

import agate
import requests
import pithy.meta as meta

from http import HTTPStatus
from bs4 import BeautifulSoup
from pithy.path_encode import path_for_url
from pithy.io import out_json, read_json, read_jsons
from pithy.fs import path_exists, path_join, split_dir_name, split_stem_ext, list_dir, path_ext


build_dir = '_build'
info_name = '_muck_info.json'

reserved_names = {
  'clean',
  'clean-all',
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
  'source handler for csv (comma separated values) files.'
  return agate.Table.from_csv(path)

def _source_html(path):
  'source handler for html.'
  with open(path) as f:
    return BeautifulSoup(f, 'html.parser')

def _source_json(path, record_types=()):
  'source handler for json files.'
  with open(path) as f:
    return read_json(f, record_types=record_types)

def _source_jsons(path, record_types=()):
  'source handler for jsons (json stream) files.'
  with open(path) as f:
    return read_jsons(f, record_types=record_types)


_source_dispatch = meta.dispatcher_for_names(prefix='_source_', default_fn=open)

def source(target_path, ext=None, **kwargs):
  '''
  Open a dependency and parse it based on its file extension.
  
  Additional keyword arguments are passed to the specific source function matching ext:
  - json, jsons: record_types.

  Muck's static analysis looks specifically for this function to infer dependencies;
  the target_path argument must be a string literal.
  '''
  # TODO: optional open_fn argument?

  path = actual_path_for_target(target_path)
  if ext is None:
    ext = path_ext(path)
  try:
    return _source_dispatch(ext.lstrip('.'), path, **kwargs)
  except FileNotFoundError:
    errFL('muck.source cannot open path: {}', path)
    if path != target_path:
      errFL('note: nor does a file exist at source path: {}', target_path)
    raise


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
      msg = 'fetch failed with HTTP code: {}: {}; {}.'.format(s.code, s.phrase, s.description)
  if msg is not None:
    raise HTTPError(msg)
  return r


def fetch(url, expected_status_code=200, headers={}, timeout=4, delay=0,
  delay_range=0):
  'Muck API to fetch a url.'
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


def source_url(url, ext=None, expected_status_code=200, headers={}, timeout=4, delay=0,
  delay_range=0, **kwargs):
  # note: implementing uncached requests efficiently requires new versions of the source functions;
  # these will take a text argument instead of a path argument.
  # alternatively, the source functions could be reimplemented to take text strings,
  # or perhaps streams.
  # in the uncached case, muck would do the open and read.
  path = fetch(url, expected_status_code=expected_status_code, headers=headers,
    timeout=timeout, delay=delay, delay_range=delay_range)
  return source(path, ext=ext, **kwargs)


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


# module exports.
__all__ = [
  'HTTPError',
  'fetch',
  'source',
  'source_url',
  'source_for_target',
]  

