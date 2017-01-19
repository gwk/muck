# Dedicated to the public domain under CC0: https://creativecommons.org/publicdomain/zero/1.0/.

import ast
import re

from .pithy.io import errF, failF
from .pithy.fs import is_file, path_dir, path_join
from .paths import has_wilds, paths_from_range_items

# these functions are recognized by the static analyzer.
from . import load, load_many, open_dep, transform
dep_fn_names = tuple(fn.__name__ for fn in (load, load_many, open_dep, transform))


def py_dependencies(src_path, src_file, dir_names):
  'Calculate dependencies for a .py (python3 source) file.'
  src_text = src_file.read()
  try: tree = ast.parse(src_text, filename=src_path)
  except SyntaxError as e:
    failF('muck error: {}:{}:{}: syntax error.\n  {}  {}^',
      src_path, e.lineno, e.offset, e.text, ' ' * (e.offset - 1))

  for node in ast.walk(tree):
    if isinstance(node, ast.Call):
      yield from py_dep_call(src_path, node)
    elif isinstance(node, ast.Import):
      for alias in node.names:
        yield from py_dep_import(src_path, alias.name, dir_names)
    elif isinstance(node, ast.ImportFrom):
      yield from py_dep_import(src_path, node.module, dir_names)


def py_dep_import(src_path, module_name, dir_names):
  'Calculate dependencies for a Python ast.Import or ast.ImportFrom node.'
  src_dir = path_dir(src_path)
  leading_dots_count = re.match('\.*', module_name).end()
  module_parts = ['..'] * leading_dots_count + module_name[leading_dots_count:].split('.')
  module_path = path_join(src_dir, *module_parts) + '.py'
  if is_file(module_path):
    yield module_path


def py_dep_call(src_path, call):
  'Calculate dependencies for a Python ast.Call node.'
  func = call.func
  if not isinstance(func, ast.Attribute): return
  if not isinstance(func.value, ast.Name): return
  # TODO: dispatch to handlers for all known functions.
  # TDOO: add handler for source_url to check that repeated (url, target) pairs are consistent across entire project.
  if func.value.id != 'muck': return
  name = func.attr
  if name not in dep_fn_names: return
  if len(call.args) < 1:
    py_fail(src_path, call, 'first argument must be a string literal; found no arguments')
  arg0 = call.args[0]
  if not isinstance(arg0, ast.Str):
    py_fail(src_path, arg0, 'first argument must be a string literal; found {}', type(arg0).__name__)
  dep_path = arg0.s # the string value from the ast.Str literal.
  if name == load_many.__name__:
    items = [eval_arg(src_path, i, arg) for (i, arg) in enumerate(call.args[1:])]
  else:
    items = []
  for vars, path in paths_from_range_items(wildcard_path=dep_path, items=items):
    yield path


def eval_arg(src_path, index, arg):
  if isinstance(arg, ast.Tuple):
    return eval_tuple(src_path, arg)
  py_fail(src_path, arg, 'argument {} literal must be a pair of integers; found {}', index, type(arg).__name__)


def eval_tuple(src_path, arg):
  if len(arg.elts) != 2:
    py_fail(src_path, arg, 'load_range', 'range argument tuple must be a pair')
  s, e = arg.elts
  if not isinstance(s, ast.Num) or not isinstance(s.n, int):
    py_fail(src_path, s, 'load_range', 'range argument tuple start must be an integer literal')
  if not isinstance(e, ast.Num) or not isinstance(e.n, int):
    py_fail(src_path, e, 'load_range', 'range argument tuple end must be an integer literal')
  return (s.n, e.n)


def py_fail(src_path, node, fmt, *items):
  failF('muck error: {}:{}:{}: {}.', src_path, node.lineno, node.col_offset + 1, fmt.format(*items))

