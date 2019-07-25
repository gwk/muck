# Dedicated to the public domain under CC0: https://creativecommons.org/publicdomain/zero/1.0/.

from .pithy.fs import DirEntries, is_file, path_dir, path_join, path_split, norm_path
from .pithy.io import read_line_from_path
from typing import Any, Dict, Iterable, Optional, TextIO, Tuple
import ast
import re


def src_error(path:str, line1:int, col1:int, msg:str, text:str=None) -> SystemExit:
  pad = ' ' * (col1 - 1)
  if text is None:
    text = read_line_from_path(path, line0=line1-1, default='<MISSING>')
  return SystemExit(f'muck error: {path}:{line1}:{col1}: {msg}.\n  {text}\n  {pad}^')


def node_error(path:str, node:ast.AST, msg:str) -> SystemExit:
  return src_error(path, node.lineno, node.col_offset + 1, msg)


def py_dependencies(target:str, src_path:str, dir_entries:DirEntries) -> Iterable[str]:
  'Calculate dependencies for a .py (python3 source) file.'
  src_dir = path_dir(src_path)
  src_dir_parts = path_split(src_dir)
  search_dirs = [src_dir, '.'] # The local directories, in order, that will be searched by python at startup.
  with open(src_path) as f:
    src_text = f.read()
  try: tree = ast.parse(src_text, filename=src_path)
  except SyntaxError as e:
    raise src_error(src_path, e.lineno, e.offset or 0, 'syntax error', (e.text or '').rstrip('\n')) from e

  def extract_import(module_str:Optional[str]) -> Optional[str]:
    if module_str is None: raise ValueError
    lead_dots = re.match('\.+', module_str)
    if lead_dots: # Relative import.
      leading_dots_count = lead_dots.end()
      back_parts = ['..'] * leading_dots_count
      named_parts = module_str[leading_dots_count:].split('.')
      module_parts = src_dir_parts + back_parts + named_parts
    else:
      module_parts = module_str.split('.')
    module_dir = path_join('.', *module_parts[:-1])
    module_name = module_parts[-1] + '.py'
    for search_dir in search_dirs:
      cand_dir = norm_path(path_join(search_dir, module_dir))
      try: cand_entries = dir_entries[cand_dir]
      except KeyError: continue
      for e in cand_entries:
        if e.name.startswith(module_name):
          return norm_path(path_join(cand_dir, module_name))
    return None

  for node in ast.walk(tree):
    if isinstance(node, ast.Import):
      for alias in node.names:
        n = extract_import(alias.name)
        if n: yield n
    elif isinstance(node, ast.ImportFrom):
      n = extract_import(node.module)
      if n: yield n
