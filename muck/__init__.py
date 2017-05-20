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
from .pithy.io import stderr, errL, errSL
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

def dst_file(encoding='UTF-8', **kwargs: str) -> IO:
  '''
  Open an output file for writing, expanding target path formatters with `kwargs`.

  This function can be used to get a binary output file handle using the `binary` parameter.
  It can also be used to output many files from a single script.
  '''
  global _manifest_file
  src = argv[0]
  if not has_formatter(src): # single destination; no need for manifest.
    if kwargs:
      raise Exception(f'source path contains no formatters but bindings provided to `dst_file`: {src}')
    return _std_open(dflt_prod_path_for_source(src) + tmp_ext, mode=('wb' if encoding is None else 'w'))
  args = tuple(sorted(kwargs.items())) # need kwargs as a hash key.
  if args in _dst_vars_opened:
    raise Exception(f'file already opened for `dst_file` arguments: {args}')
  _dst_vars_opened.add(args)
  path = dst_path(argv, kwargs) + tmp_ext
  if _manifest_file is None:
    _manifest_file = _std_open(manifest_path(argv), 'w')
  print(path, file=_manifest_file)
  if encoding is None: # binary.
    return _std_open(path, mode='wb')
  else:
    return _std_open(path, mode='w', encoding=encoding)


_open_parameters = frozenset({'buffering', 'encoding', 'errors', 'newline'})

_deps_recv: Optional[TextIO] = None
_deps_send: Optional[TextIO] = None

def _open(path: str, buffering=-1, encoding='UTF-8', errors=None, newline=None) -> IO:
  global _deps_recv, _deps_send
  if not path.startswith('/') and not path.startswith('../'):
    if _deps_recv is None:
      try:
        recv = int(os.environ['DEPS_RECV'])
        send = int(os.environ['DEPS_SEND'])
      except KeyError: pass # not running as child of muck build process.
      else:
        _deps_recv = cast(TextIO, _std_open(int(recv), 'r'))
        _deps_send = cast(TextIO, _std_open(int(send), 'w'))
    if _deps_recv:
      print(path, file=_deps_send, flush=True)
      ack = _deps_recv.readline()
      if ack != path + '\n':
        raise Exception(f'muck.open: dependency {path} was not acknowledged: {ack!r}')
  if encoding is None: # binary.
    return _std_open(path, mode='rb', buffering=buffering, errors=errors, newline=newline)
  else: # text.
    return _std_open(path, buffering=buffering, encoding=encoding, errors=errors, newline=newline)


def open(path: str, **kwargs) -> IO:
  '''
  Open a dependency for reading.
  Compared to standard `open`, this function does not support integer file descriptors for the path argument,
  nor the `closefd` and `opener` parameters,
  because their usage is fundamentally at odds with dependency tracking.
  `mode` is also unsupported, because the API is read-only; binary mode is implied by `encoding=None`.
  TODO: support the other pathlike objects.
  '''
  if '{' in path:
    path = path.format(**bindings_from_argv(sys.argv))
  return _open(path, **kwargs)


LoadFn = Callable[..., Any]

class Loader(NamedTuple):
  ext: str
  fn: LoadFn
  open_args: Tuple[Tuple[str, Any], ...]


_loaders: Dict[str, Loader] = {}

def add_loader(ext: str, _fn: LoadFn, buffering=-1, encoding='UTF-8', errors=None, newline=None, _dflt=False) -> None:
  '''
  Register a loader function, which will be called by `muck.load` for matching `ext`.
  `buffering`, `encoding`, `errors`, and `newline` are all passed on to `open` when it is called by `load`.
  '''
  if not ext.startswith('.'):
    raise ValueError(f"file extension does not start with '.': {ext!r}")
  if not _dflt:
    try: prev_loader = _loaders[ext]
    except KeyError: pass
    else: raise Exception(f'add_loader: extension previously registered: {ext!r}; loader: {prev_loader!r}')
  _loaders[ext] = Loader(ext=ext, fn=_fn, open_args=(
    ('buffering', buffering), ('encoding', encoding), ('errors', errors), ('newline', newline)))


def load_txt(f: TextIO, clip_ends=False) -> Iterable[str]:
  if clip_ends: return (line.rstrip('\n\r') for line in f)
  return f


def load_xls(file: BinaryIO) -> Any:
  from xlrd import open_workbook # type: ignore
  # Unfortunately load_xls will not take an open file handle.
  # Since we might be passing in an in-memory file like ArchiveFile,
  # the best we can do for now is always read file contents into memory.
  # Alternative would be to make ArchiveFile conform to mmap protocol,
  # or patch xlrd to support passing in an open binary file descriptor.
  return open_workbook(filename=None, logfile=stderr, file_contents=file.read())


def load_zip(f: BinaryIO, single_name=None, single_ext=None, **kwargs:Any) -> Any:
  from .pithy.archive import Archive
  archive = Archive(f)
  if single_name is None:
    if single_ext is not None or kwargs:
      raise ValueError('load_zip: `single_name` not specified; no other options should be set')
    return archive
  # load single file.
  for file in archive: # type: ignore
    if file.name != single_name: continue
    return load(file, ext=single_ext, **kwargs)
  raise LookupError(f'load_zip: could not find specified single_name in archive: {single_name!r}; archive.file_names: {archive.file_names}')


add_loader('.txt',    load_txt,   _dflt=True)
add_loader('.css',    load_txt,   _dflt=True)
add_loader('.csv',    load_csv,   _dflt=True, newline='') # newline specified as per footnote in csv module.
add_loader('.json',   load_json,  _dflt=True)
add_loader('.jsonl',  load_jsonl, _dflt=True)
add_loader('.jsons',  load_jsons, _dflt=True)
add_loader('.xls',    load_xls,   _dflt=True, encoding=None)
add_loader('.zip',    load_zip,   _dflt=True, encoding=None)


def load(file_or_path: Any, ext:str=None, **kwargs) -> Any:
  '''
  Select an appropriate loader based on the file extension, or `ext` if specified.

  If no loader is found, raise an error.

  If a loader is found, then `open` is called with the `open_args` registered by `add_loader`,
  except updated by any values in `kwargs` whose keys match the loader `open_keys`.
  The remaining `kwargs` are passed to the loader function.
  '''
  is_file = hasattr(file_or_path, 'read')
  if is_file:
    if ext is None:
      try: path = file_or_path.name
      except AttributeError as e:
        raise ValueError(f'load: file object does not have `name` attribute and no `ext` specified: {file_or_path}') from e
      ext = path_ext(path)
  else:
    path = file_or_path
    if '{' in path: # might have format; expand.
      path = path.format(**bindings_from_argv(sys.argv))
    if ext is None:
      ext = path_ext(path)

  loader = _loaders[ext]
  open_args = dict(loader.open_args)
  for k in tuple(open_args):
    try: v = kwargs[k]
    except KeyError: pass
    else:
      open_args[k] = v
      del kwargs[k] # this arg goes to open, not load. safe because kwargs is local.

  if is_file:
    file = file_or_path
    if open_args['encoding'] is not None and not hasattr(file, 'encoding'): # want text but have binary file.
      del open_args['buffering'] # TextIOWrapper does not support this argument.
      file = TextIOWrapper(file, **open_args)
  else:
    file = open(file_or_path, **open_args)

  return loader.fn(file, **kwargs)


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
    with _std_open(path, 'wb') as f:
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
