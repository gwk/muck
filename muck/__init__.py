# Dedicated to the public domain under CC0: https://creativecommons.org/publicdomain/zero/1.0/.

'''
Muck client libary functions.
'''

import sys
assert sys.version_info.major == 3 # python 2 is not supported.

import os
import random
import time
import requests

from csv import reader as csv_reader
from http import HTTPStatus
from sys import argv
from typing import *
from typing import IO, TextIO
from urllib.parse import urlencode, urlparse

from .pithy.format import has_formatter
from .pithy.fs import make_dirs, path_dir, path_exists, path_ext, path_join, path_stem
from .pithy.io import errL
from .pithy.json_utils import load_json, load_jsonl, load_jsons
from .pithy.path_encode import path_for_url
from .pithy.transform import Transformer

from .constants import tmp_ext
from .paths import bindings_from_argv, dflt_prod_path_for_source, dst_path, manifest_path


# module exports.
__all__ = [
  'HTTPError',
  'add_loader',
  'dst_file',
  'fetch',
  'load',
  'load_url',
  'open_dep',
  'transform',
]

_dst_vars_opened: Set[Tuple[Tuple[str, str], ...]] = set()
_manifest_file = None

def dst_file(binary=False, **kwargs: str) -> IO:
  '''
  Open an output file for writing, expanding target path formatters with `kwargs`.

  This function can be used to get a binary output file handle using the `binary` parameter.
  It can also be used to output many files from a single script.
  '''
  global _manifest_file
  src = argv[0]
  mode = 'wb' if binary else 'w'
  if not has_formatter(src): # single destination; no need for manifest.
    if kwargs:
      raise Exception(f'source path contains no formatters but bindings provided to `dst_file`: {src}')
    return open(dflt_prod_path_for_source(src) + tmp_ext, mode)
  args = tuple(sorted(kwargs.items())) # need kwargs as a hash key.
  if args in _dst_vars_opened:
    raise Exception(f'file already opened for `dst_file` arguments: {args}')
  _dst_vars_opened.add(args)
  path = dst_path(argv, kwargs) + tmp_ext
  if _manifest_file is None:
    _manifest_file = open(manifest_path(argv), 'w')
  print(path, file=_manifest_file)
  return open(path, mode=mode)


_open_deps_parameters = { 'binary', 'buffering', 'encoding', 'errors', 'newline' }

_deps_recv: Optional[TextIO] = None
_deps_send: Optional[TextIO] = None

def open_dep(target_path: str, binary=False, buffering=-1, encoding=None, errors=None, newline=None) -> IO:
  '''
  Open a dependency for reading.

  Muck's static analysis looks specifically for this function to infer dependencies;
  `target_path` must be a string literal.
  '''
  global _deps_recv, _deps_send
  if _deps_recv is None:
    try:
      recv = int(os.environ['DEPS_RECV'])
      send = int(os.environ['DEPS_SEND'])
    except KeyError: pass # not running as child of muck build process.
    else:
      _deps_recv = cast(TextIO, open(int(recv), 'r'))
      _deps_send = cast(TextIO, open(int(send), 'w'))
  if _deps_recv:
    print(target_path, file=_deps_send, flush=True)
    ack = _deps_recv.readline()
    if ack != target_path + '\n': raise Exception(f'muck.open_dep: dependency {target_path} was not acknowledged: {ack!r}')
  return open(target_path, mode=('rb' if binary else 'r'), buffering=buffering, encoding=encoding, errors=errors, newline=newline)


_loaders: Dict[str, Tuple[Callable[..., Any], Dict[str, Any]]] = {}

def add_loader(ext: str, fn: Callable[..., Any], **open_dep_kwargs) -> None:
  '''
  Register a loader function, which will be called by `muck.load` for matching `ext`.
  Any keyword arguments passed here will be used as defaults when calling `open_dep`,
  and will determine which keyword arguments passed to `muck.load` will be passed to open_dep;
  all other keyword arguments will be passed to `fn`.
  '''
  if not ext.startswith('.'):
    raise ValueError(f"file extension does not start with '.': {ext!r}")
  if ext not in _default_loaders:
    try: existing_fn, _ = _loaders[ext]
    except KeyError: pass
    else: raise Exception(f'add_loader: extension previously registered: {ext!r}; fn: {existing_fn!r}')
  for k, v in sorted(open_dep_kwargs.items()):
    if k not in _open_deps_parameters: raise KeyError(k)
  _loaders[ext] = (fn, open_dep_kwargs)


def load_txt(f: TextIO, clip_ends=False) -> Iterable[str]:
  if clip_ends: return (line.rstrip('\n') for line in f)
  return f


_default_loaders: Tuple[Tuple[str, Callable[..., Any], Dict[str, Any]], ...] = (
  ('.css',   load_txt, {}),
  ('.csv',   csv_reader, dict(newline='')),
  ('.json',  load_json, dict(encoding=None)),
  ('.jsonl', load_jsonl, dict(encoding=None)),
  ('.jsons', load_jsons, dict(encoding=None)),
  ('.txt',   load_txt, dict(binary=False, buffering=-1, encoding=None, errors=None, newline=None)),
)

for ext, fn, args in _default_loaders:
  add_loader(ext, fn, **args)

def load(target_path: str, ext=None, **kwargs: Any) -> Any:
  '''
  Select an appropriate loader based on the file extension, or `ext` if specified.

  If a loader is found, then `open_dep` is called with the default `open_dep_kwargs` registered by `add_loader`,
  except updated by any values with matching keys in `kwargs`.
  The remaining `kwargs` are passed to the loader function registered by `add_loader`.
  Thus, keyword arguments passed to `load` get divvied up between `open_dep` and the custom load function.

  If no loader is found, raise an error.

  Muck's static analysis looks specifically for this function to infer dependencies;
  `target_path` must be a string literal.
  '''
  bindings = bindings_from_argv(sys.argv)
  subs_path = target_path.format(**bindings)
  if ext is None:
    ext = path_ext(subs_path)
  elif not isinstance(ext, str): raise TypeError(ext)
  try: load_fn, std_open_args = _loaders[ext]
  except KeyError:
    errL(f'ERROR: No loader found for target: {subs_path!r}')
    errL(f'NOTE: extension: {ext!r}')
    raise
  open_args = std_open_args.copy()
  # transfer all matching kwargs to open_args.
  for k in _open_deps_parameters:
    try: v = kwargs[k]
    except KeyError: continue
    open_args[k] = v
    del kwargs[k] # only pass this arg to open_deps; del is safe because kwargs has local lifetime.
  file = open_dep(subs_path, **open_args)
  return load_fn(file, **kwargs)


class HTTPError(Exception):
  def __init__(self, msg: str, request: Any) -> None:
    super().__init__(msg)
    self.request = request
    self.status_code = 0 if request is None else request.status_code


def _fetch(url: str, timeout: int, headers: Dict[str, str], expected_status_code: int) -> Any:
  '''
  wrap the call to `get` with try/except that flattens any exception trace into an HTTPError.
  without this, a backtrace due to a network failure is massive, involves multiple exceptions,
  and is mostly irrelevant to the caller.
  '''
  r = None
  try:
    msg = None
    r = requests.get(url, timeout=timeout, headers=headers)
  except Exception as e:
    args_str = ', '.join(str(a) for a in e.args)
    msg = f'fetch failed with exception: {type(e).__name__}: {args_str}' # TODO: use `raise from e` here.
  else:
    if r.status_code != expected_status_code:
      s = HTTPStatus(r.status_code)
      msg = f'fetch failed with HTTP code: {s.value}: {s.phrase}; {s.description}.'
  if msg is not None:
    raise HTTPError(msg=msg, request=r)
  return r


def fetch(url: str, cache_path: str=None, params: Dict[str, str]={}, headers: Dict[str, str]={}, expected_status_code=200, timeout=4, delay=0, delay_range=0, spoof=False) -> str:
  "Fetch the data at `url` and save it to a path in the '_fetch' directory derived from the URL."
  if params:
    if '?' in url: raise ValueError("params specified but url already contains '?'")
    url += '?' + urlencode(params)
  if not cache_path:
    cache_path = path_for_url(url)
  path = path_join('../_fetch', cache_path)
  if not path_exists(path):
    errL(f'fetch: {url}')
    if spoof:
      h = spoofing_headers()
      h.update(headers)
      headers = h
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


def load_url(url: str, ext: str=None, cache_path: str=None, params: Dict[str, str]={}, headers: Dict[str, str]={}, expected_status_code=200, timeout=4, delay=0, delay_range=0, spoof=False, **kwargs: Any) -> Any:
  'Fetch the data at `url` and then load using `muck.load`.'
  # note: implementing uncached requests efficiently requires new versions of the source functions;
  # these will take a text argument instead of a path argument.
  # alternatively, the source functions could be reimplemented to take text strings,
  # or perhaps streams.
  # in the uncached case, muck would do the open and read.
  if ext is None:
    # extract the extension from the url path;
    # load will try to extract it from the encoded path,
    # which may have url path/parameters/query/fragment.
    if cache_path:
      ext = path_ext(cache_path)
    else:
      parts = urlparse(url)
      ext = path_ext(parts.path)
  path = fetch(url, cache_path=cache_path, params=params, headers=headers, expected_status_code=expected_status_code,
    timeout=timeout, delay=delay, delay_range=delay_range, spoof=spoof)
  return load(path, ext=ext, **kwargs)


def spoofing_headers() -> Dict[str, str]:
  # Headers that Safari currently sends. TODO: allow imitating other browsers?
  return {
    'DNT': '1',
    'Upgrade-Insecure-Requests': '1',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Cache-Control': 'max-age=0',
    'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_2) AppleWebKit/602.3.12 (KHTML, like Gecko) Version/10.0.2 Safari/602.3.12',
  }


def transform(target_path: str, ext: str=None, **kwargs: Any) -> Transformer:
  '''
  Open a dependency using muck.load and then transform it using pithy.Transformer.

  Additional keyword arguments are passed to the specific load function matching `ext`;
  see muck.load for details.

  Muck's static analysis looks specifically for this function to infer dependencies;
  `target_path` must be a string literal.
  '''
  seq = load(target_path, ext=ext, **kwargs)
  product = dflt_prod_path_for_source(argv[0]) # TODO: needs to process wildcards.
  return Transformer(seq, log_stem=path_stem(product) + '.')
