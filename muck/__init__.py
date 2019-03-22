# Dedicated to the public domain under CC0: https://creativecommons.org/publicdomain/zero/1.0/.

'''
Muck client libary functions.
'''

import os
import random
import shlex
import sys
import time
from builtins import open as _std_open
from http import HTTPStatus
from io import TextIOWrapper
from sys import argv
from typing import IO, Any, BinaryIO, Dict, Set, TextIO, Tuple
from urllib.parse import urlencode, urlparse

from .paths import bindings_from_args, dflt_prod_path_for_source, dst_path
from .pithy.format import has_formatter
from .pithy.fs import (Path, PathOrFd, make_dirs, move_file, path_dir, path_exists, path_ext, path_join, path_stem,
  split_stem_ext)
from .pithy.io import errL, errSL, stderr
from .pithy.loader import FileOrPath, add_loader, load as _load
from .pithy.path_encode import path_for_url
from .pithy.task import runCO
from .pithy.transform import Transformer


assert sys.version_info.major == 3 # python 2 is not supported.


# module exports.
__all__ = [
  'HTTPError',
  'argv',
  'add_loader',
  'dst_file',
  'fetch',
  'load',
  'load_url',
  'open',
  'transform',
]


src = argv[0]
args = tuple(argv[1:])

# Normally, target is provided by the environment.
# However we want to allow scripts to run standalone if possible.
# For safety, check that the calculated target is identical to the provided one;
# in the future we could speed this up slightly by assuming as much.
target = path_stem(src)
if '{' in target: # Contains either formatter or escaped brace; expand.
  target = target.format(**bindings_from_args(src=src, args=args))
try: assert target == os.environ['MUCK_TARGET']
except KeyError: pass # running standalone (or the Muck parent process).


_dst_vars_opened:Set[Tuple[Tuple[str, str], ...]] = set()

def dst_file(encoding='UTF-8', **kwargs:str) -> IO:
  '''
  Open an output file for writing, expanding target path formatters with `kwargs`.
  '''
  kwargs_tuple = tuple(sorted(kwargs.items())) # need kwargs as a hash key.
  if kwargs_tuple in _dst_vars_opened:
    raise Exception(f'file already opened for `dst_file` arguments: {kwargs_tuple}')
  if not has_formatter(src): # single destination.
    if kwargs:
      raise Exception(f'source path contains no formatters but bindings provided to `dst_file`: {src}')
    return _std_open(dflt_prod_path_for_source(src), mode=('wb' if encoding is None else 'w'))
  _dst_vars_opened.add(kwargs_tuple)
  path = dst_path(src, args, kwargs)
  if encoding is None: # binary.
    return _std_open(path, mode='wb')
  else:
    return _std_open(path, mode='w', encoding=encoding)


def load(file_or_path:FileOrPath, ext:str=None, **kwargs) -> Any:
  '''
  Select an appropriate loader based on the file extension, or `ext` if specified.
  This function is a wrapper around pithy.loader.load; see that function's documentation for details.
  The difference is that this version does target path expension,
  and uses muck.open instead of the standard io.open
  to communicate dependencies to the parent build process.
  '''
  if isinstance(file_or_path, str) and '{' in file_or_path: # might have format; expand.
      file_or_path = file_or_path.format(**bindings_from_args(src=src, args=args))
  return _load(file_or_path, ext=ext, **kwargs)


def open(path:PathOrFd, **kwargs) -> IO:
  '''
  Wrapper around the standard system open that formats arguments into the file name appropriately.
  '''
  if isinstance(path, str) and '{' in path: # might have format; expand.
    path = path.format(**bindings_from_args(src=src, args=args))
  return _std_open(path, **kwargs)


class HTTPError(Exception):
  def __init__(self, msg:str, curl_code:int=0, status_code:int=-1) -> None:
    super().__init__(msg)
    self.curl_code = curl_code
    self.status_code = status_code


def fetch(url:str, cache_path:str=None, params:Dict[str, str]={}, headers:Dict[str, str]={}, expected_status_code=200, timeout=30, delay=0, delay_range=0, spoof_ua=False) -> str:
  "Fetch the data at `url` and save it to a path in the '_fetch' directory derived from the URL."
  if params:
    if '?' in url: raise ValueError("params specified but url already contains '?'")
    url += '?' + urlencode(params)
  if not cache_path:
    cache_path = path_for_url(url)
  path = path_join('../_fetch', cache_path)
  path_tmp = path_join('../_fetch/tmp', cache_path)
  if not path_exists(path):
    cmd = ['curl', url, '--write-out', '%{http_code}', '--output', path_tmp]
    if spoof_ua:
      h = spoofing_headers()
      h.update(headers) # any explicit headers override the spoofing values.
      headers = h
    for k, v in headers.items():
      cmd.extend(('--header', f'{k}: {v}'))
    make_dirs(path_dir(path_tmp))
    errSL('fetch:', *[shlex.quote(word) for word in cmd])
    curl_code, output = runCO(cmd)
    if curl_code != 0:
      raise HTTPError(f'curl failed with code: {curl_code}', curl_code=curl_code)
      # TODO: copy the error code explanations from `man curl`? Or parse them on the fly?
    try:
      status_code = int(output)
      status = HTTPStatus(status_code)
    except ValueError as e:
      raise HTTPError(f'curl returned strange HTTP code: {repr(output)}') from e
    if status_code != expected_status_code:
      raise HTTPError(msg=f'fetch failed with HTTP code: {status.value}: {status.phrase}; {status.description}.',
        status_code=status_code)
    make_dirs(path_dir(path))
    move_file(path_tmp, path)
    sleep_min = delay - delay_range * 0.5
    sleep_max = delay + delay_range * 0.5
    sleep_time = random.uniform(sleep_min, sleep_max)
    if sleep_time > 0:
      time.sleep(sleep_time)
  return path


def load_url(url:str, ext:str=None, cache_path:str=None, params:Dict[str, str]={}, headers:Dict[str, str]={}, expected_status_code=200, timeout=30, delay=0, delay_range=0, spoof_ua=False, **kwargs:Any) -> Any:
  'Fetch the data at `url` and then load using `muck.load`.'
  if ext is None:
    if cache_path:
      ext = path_ext(cache_path)
    else:
      # extract the extension from the url path;
      # we cannot leave it to load because it sees the encoded path,
      # which may have url path/parameters/query/fragment.
      parts = urlparse(url)
      ext = path_ext(parts.path) # TODO: support compound extensions, e.g. 'tar.gz'.
  path = fetch(url, cache_path=cache_path, params=params, headers=headers, expected_status_code=expected_status_code,
    timeout=timeout, delay=delay, delay_range=delay_range, spoof_ua=spoof_ua)
  return load(path, ext=ext, **kwargs)


def spoofing_headers() -> Dict[str, str]:
  # Headers that Safari sent at one point. Not sure how up-to-date these ought to be.
  # TODO: allow imitating other browsers?
  return {
    'DNT': '1',
    'Upgrade-Insecure-Requests': '1',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Cache-Control': 'max-age=0',
    'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_2) AppleWebKit/602.3.12 (KHTML, like Gecko) Version/10.0.2 Safari/602.3.12',
  }


def transform(target_path:str, ext:str=None, **kwargs:Any) -> Transformer:
  '''
  Open a dependency using muck.load and then transform it using pithy.Transformer.

  Additional keyword arguments are passed to the specific load function matching `ext`;
  see muck.load for details.
  '''
  seq = load(target_path, ext=ext, **kwargs)
  product = dflt_prod_path_for_source(src) # TODO: needs to process wildcards.
  return Transformer(seq, log_stem=path_stem(product) + '.')
