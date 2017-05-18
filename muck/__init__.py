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

from builtins import open as _std_open
from http import HTTPStatus
from io import TextIOWrapper
from sys import argv
from typing import *
from typing import IO, TextIO, BinaryIO
from urllib.parse import urlencode, urlparse

from .pithy.csv_utils import load_csv
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
  'argv',
  'add_loader',
  'dst_file',
  'fetch',
  'load',
  'load_url',
  'open',
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


OpenFn = Callable[..., IO]

_open_parameters = frozenset({'mode', 'buffering', 'encoding', 'errors', 'newline'})

_deps_recv: Optional[TextIO] = None
_deps_send: Optional[TextIO] = None

def open(target_path: str, mode='r', buffering=-1, encoding=None, errors=None, newline=None) -> IO:
  '''
  Open a dependency for reading.
  '''
  global _deps_recv, _deps_send
  if not target_path.startswith('/') and not target_path.startswith('../'):
    if _deps_recv is None:
      try:
        recv = int(os.environ['DEPS_RECV'])
        send = int(os.environ['DEPS_SEND'])
      except KeyError: pass # not running as child of muck build process.
      else:
        _deps_recv = cast(TextIO, _std_open(int(recv), 'r'))
        _deps_send = cast(TextIO, _std_open(int(send), 'w'))
    if _deps_recv:
      print(target_path, file=_deps_send, flush=True)
      ack = _deps_recv.readline()
      if ack != target_path + '\n':
        raise Exception(f'muck.open: dependency {target_path} was not acknowledged: {ack!r}')
  return _std_open(target_path, mode=mode, buffering=buffering, encoding=encoding, errors=errors, newline=newline)


LoadFn = Callable[..., Any]

class Loader(NamedTuple):
  ext: str
  fn: LoadFn
  open_keys: Tuple[str, ...]
  open_args: Tuple[Tuple[str, Any], ...]


_loaders: Dict[str, Loader] = {}

def add_loader(ext: str, _fn: LoadFn, _dflt=False, open_keys:Iterable[str]=(), **open_args:Any) -> None:
  '''
  Register a loader function, which will be called by `muck.load` for matching `ext`.
  `open_keys` specifies the names of keyword arguments that, when passed to `load`, will be forwarded on to `open`.
  `open_args` (as kwargs) will always be passed on to `open` but cannot be overridden.

  In other words, when `load` is called with a path whose extension matches a given loader,
  keys that are present in `open_keys` are passed on to `open`;
  all other keyword arguments are passed on to `_fn`.
  '''
  if not ext.startswith('.'):
    raise ValueError(f"file extension does not start with '.': {ext!r}")
  if not _dflt:
    try: prev_loader = _loaders[ext]
    except KeyError: pass
    else: raise Exception(f'add_loader: extension previously registered: {ext!r}; loader: {prev_loader!r}')
  for k in open_keys:
    if k not in _open_parameters: raise KeyError(f'bad parameter name for `open` in `open_keys`: {k}')
  for k in open_args:
    if k not in _open_parameters: raise KeyError(f'bad parameter name for `open` in `open_args`: {k}')
    if k in open_keys: raise KeyError(f'`open_keys` key repeated in `open_args`: {k}')
  _loaders[ext] = Loader(ext=ext, fn=_fn, open_keys=tuple(open_keys), open_args=tuple(open_args.items()))


def load_txt(f: TextIO, clip_ends=False) -> Iterable[str]:
  if clip_ends: return (line.rstrip('\n') for line in f)
  return f


def load_zip(f: BinaryIO, load=True, load_single=False, load_ext:str=None, **kwargs:Any) -> Any:
  from zipfile import ZipFile
  z = ZipFile(f)
  if not load and not load_single and not load_ext:
    if kwargs:
      raise ValueError('load_zip: no load options results in a ZipFile, and implies that no other options should be set')
    return z
  paths = z.namelist()
  if load_single:
    if len(paths) != 1: raise Exception(f'load_zip: expected single file in archive; found: {paths}')
    for el in _zip_load_gen(z, paths, load_ext, kwargs): return el
  else:
    return _zip_load_gen(z, paths, load_ext, kwargs)


def _zip_load_gen(z: Any, paths: List[str], ext:Optional[str], kwargs:Dict[str, Any]) -> Any:
  'Factored out to accommodate load_single option.'

  def open_within_zip(path: str, mode='r', buffering=-1, encoding=None, errors=None, newline=None) -> IO:
    '''
    Imitates load_dep within a zip file.
    Note: `buffering` is ignored, as it appears to have no effect for TextIOWrapper in read mode.
    '''
    f: IO = z.open(path)
    if 'b' in mode:
      if encoding is not None or errors is not None or newline is not None:
        raise ValueError('load_zip: binary mode implies that `encoding`, `errors`, and `newline` should not be set')
      return f
    else:
      return TextIOWrapper(f, encoding=encoding, errors=errors, newline=newline)

  for path in paths:
    if path.endswith('/'): continue # ignore directories.
    yield load(path, open=open_within_zip, ext=ext, **kwargs)


add_loader('.txt',    load_txt,   _dflt=True, open_keys=_open_parameters)
add_loader('.css',    load_txt,   _dflt=True, open_keys=_open_parameters)
add_loader('.csv',    load_csv,   _dflt=True, open_keys={'encoding'}, newline='') # newline specified as per footnote in csv module.
add_loader('.json',   load_json,  _dflt=True, encoding=None)
add_loader('.jsonl',  load_jsonl, _dflt=True, encoding=None)
add_loader('.jsons',  load_jsons, _dflt=True, encoding=None)
add_loader('.zip',    load_zip,   _dflt=True, mode='rb')


def load(target_path: str, open:OpenFn=open, ext:str=None, **kwargs: Any) -> Any:
  '''
  Select an appropriate loader based on the file extension, or `ext` if specified.

  If no loader is found, raise an error.

  If a loader is found, then `open` is called with the `open_args` registered by `add_loader`,
  except updated by any values in `kwargs` whose keys match the loader `open_keys`.
  The remaining `kwargs` are passed to the loader function.
  '''
  if kwargs.get('mode', 'r') not in ('r', 'rb', 'br'): raise ValueError(f'invalid read mode: {kwargs["mode"]}')
  bindings = bindings_from_argv(sys.argv)
  path = target_path.format(**bindings)
  fn, open_args, load_args = _get_loader_fn_and_args(path, ext, kwargs)
  file = open(path, **open_args)
  return fn(file, **load_args)


def _get_loader_fn_and_args(path: str, ext:Optional[str], kwargs:Any) -> Tuple[LoadFn, Dict[str, Any], Dict[str, Any]]:
  if ext is None:
    ext = path_ext(path)
  try: loader = _loaders[ext]
  except KeyError:
    errL(f'ERROR: No loader found for path: {path!r}; extension: {ext!r}')
    raise
  open_args = dict(loader.open_args)
  load_args = dict(kwargs) # copy argument to be safe.
  # transfer all kwargs matching open_keys to open_args.
  for k in loader.open_keys:
    try: v = kwargs[k]
    except KeyError: continue
    open_args[k] = v
    del load_args[k]
  return loader.fn, open_args, load_args


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


def fetch(url: str, cache_path: str=None, params: Dict[str, str]={}, headers: Dict[str, str]={}, expected_status_code=200, timeout=30, delay=0, delay_range=0, spoof=False) -> str:
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


def load_url(url: str, ext: str=None, cache_path: str=None, params: Dict[str, str]={}, headers: Dict[str, str]={}, expected_status_code=200, timeout=30, delay=0, delay_range=0, spoof=False, **kwargs: Any) -> Any:
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
      ext = path_ext(parts.path) # TODO: support compound extensions, e.g. 'tar.gz'.
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
  '''
  seq = load(target_path, ext=ext, **kwargs)
  product = dflt_prod_path_for_source(argv[0]) # TODO: needs to process wildcards.
  return Transformer(seq, log_stem=path_stem(product) + '.')
