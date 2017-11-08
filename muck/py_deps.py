# Dedicated to the public domain under CC0: https://creativecommons.org/publicdomain/zero/1.0/.

import ast
import re

from typing import *
from typing import TextIO

from .pithy.fs import is_file, path_dir, path_join
from .pithy.io import read_line_from_path


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

  def walk_import(module_name: Optional[str], dir_names: Any) -> Iterable[str]:
    if module_name is None: raise ValueError
    src_dir = path_dir(src_path)
    leading_dots_count = re.match('\.*', module_name).end()
    module_parts = ['..'] * leading_dots_count + module_name[leading_dots_count:].split('.')
    module_path = path_join(src_dir, *module_parts) + '.py'
    if is_file(module_path):
      yield module_path

  for node in ast.walk(tree):
    if isinstance(node, ast.Import):
      for alias in node.names:
        yield from walk_import(alias.name, dir_names)
    elif isinstance(node, ast.ImportFrom):
      yield from walk_import(node.module, dir_names)
