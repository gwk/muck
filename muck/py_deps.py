# Dedicated to the public domain under CC0: https://creativecommons.org/publicdomain/zero/1.0/.

import ast
import re

from typing import *

from .pithy.io import *
from .pithy.fs import is_file, path_dir, path_join
from .paths import bindings_for_format, paths_from_format

# these functions are recognized by the static analyzer.
from . import load, load_many, open_dep, transform
dep_fn_names = tuple(fn.__name__ for fn in (load, load_many, open_dep, transform))


def src_error(path: str, line1: int, col1: int, msg: str, text: str=None) -> SystemExit:
  pad = ' ' * (col1 - 1)
  if text is None:
    text = read_line_from_path(path, line0=line1-1, default='<MISSING>')
  return SystemExit(f'muck error: {path}:{line1}:{col1}: {msg}.\n  {text}\n  {pad}^')


def node_error(path: str, node: ast.AST, msg: str) -> SystemExit:
  return src_error(path, node.lineno, node.col_offset + 1, msg) # type: ignore


def py_dependencies(src_path: str, src_file: TextIO, dir_names: Any) -> Iterable[str]:
  'Calculate dependencies for a .py (python3 source) file.'
  src_text = src_file.read()
  try: tree = ast.parse(src_text, filename=src_path)
  except SyntaxError as e:
    raise src_error(src_path, e.lineno, e.offset, 'syntax error', e.text.rstrip('\n')) from e

  # TODO: track which muck symbols have been imported.

  def walk_import(module_name: Optional[str], dir_names: Any) -> Iterable[str]:
    if module_name is None: raise ValueError
    src_dir = path_dir(src_path)
    leading_dots_count = re.match('\.*', module_name).end()
    module_parts = ['..'] * leading_dots_count + module_name[leading_dots_count:].split('.')
    module_path = path_join(src_dir, *module_parts) + '.py'
    if is_file(module_path):
      yield module_path

  def walk_call(call: ast.Call) -> Iterable[str]:
    func = call.func
    if isinstance(func, ast.Attribute):
      if not (isinstance(func.value, ast.Name) and func.value.id == 'muck'): return
      #^ TODO: use whatever name muck was imported with.
      name = func.attr
    elif isinstance(func, ast.Name):
      name = func.id # TODO: validate that this name was actually imported from muck.
    else: return
    # TODO: dispatch to handlers for all known functions.
    # TDOO: add handler for source_url to check that repeated (url, target) pairs are consistent across entire project.
    if name not in dep_fn_names: return
    if len(call.args) < 1:
      raise node_error(src_path, call, 'first argument must be a string literal; found no arguments')
    arg0 = call.args[0]
    if not isinstance(arg0, ast.Str):
      raise node_error(src_path, arg0, f'first argument must be a string literal; found {type(arg0).__name__}')
    dep_path = arg0.s # the string value from the ast.Str literal.
    if name == load_many.__name__:
      kwargs = { kw.arg : kw.value for kw in call.keywords }
      seqs = { k : eval_seq_arg(src_path, a) for k, a in bindings_for_format(dep_path, kwargs) } # type: ignore
      #^ pulls out the keyword argument AST nodes that match the format string,
      #^ then statically evaluate them.
    else:
      seqs = {}
    try:
      for path, _ in paths_from_format(format_path=dep_path, seqs=seqs, partial=True): # type: ignore
        yield path
    except Exception as e:
      raise node_error(src_path, arg0, e.args[0]) from e

  for node in ast.walk(tree):
    if isinstance(node, ast.Call):
      yield from walk_call(node)
    elif isinstance(node, ast.Import):
      for alias in node.names:
        yield from walk_import(alias.name, dir_names)
    elif isinstance(node, ast.ImportFrom):
      yield from walk_import(node.module, dir_names)


def eval_seq_arg(src_path: str, arg: str) -> Tuple:
  if isinstance(arg, ast.Call):
    return eval_call(src_path, arg)
  if isinstance(arg, (ast.List, ast.Set, ast.Tuple)):
    return tuple(eval_el(src_path, el) for el in arg.elts)
  raise node_error(src_path, arg, f'sequence argument must be statically evaluable; found {type(arg).__name__}')


def eval_el(path: str, el: Any) -> Any:
  if isinstance(el, ast.Num): return eval_int(path, el)
  if isinstance(el, ast.Str): return el.s
  raise node_error(path, el, f'sequence element must be an int or str; found {type(arg).__name__}')


def eval_call(path: str, call: ast.Call) -> Any:
  func = call.func
  if not isinstance(func, ast.Name):
    raise node_error(path, func, 'called function must be a statically evaluable name.')
  if func.id == 'range':
    args = call.args
    if not (1 <= len(call.args) <= 3):
      raise node_error(src_path, call, "'range' requires 1 to 3 arguments.")
    nat_args = tuple(eval_nat(path, a) for a in args)
    return range(*nat_args) # TODO: support negative start, stop.
  else: raise node_error(path, func, f"called function must be statically evaluable, i.e. 'range'")


def eval_int(path: str, num: ast.Num) -> int:
  if not (isinstance(num, ast.Num) or not isinstance(num.n, int)):
    raise node_error(path, num, f'expected a literal integer; found {type(num).__name__}.')
  return num.n


def eval_nat(path: str, num: ast.Num) -> int:
  n = eval_int(path, num)
  if n < 0:
    raise node_error(path, num, 'expected a non-negative literal integer.')
  return n
