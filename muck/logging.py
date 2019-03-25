# Dedicated to the public domain under CC0: https://creativecommons.org/publicdomain/zero/1.0/.

from typing import Any

from .pithy.ansi import RST_ERR, TXT_L_ERR, TXT_Y_ERR
from .pithy.io import errL


def note(path:str, *items:Any) -> None:
  errL(TXT_L_ERR, f'muck note: {path}: ', *items, RST_ERR)

def warn(path:str, *items:Any) -> None:
  errL(TXT_Y_ERR, f'muck WARNING: {path}: ', *items, RST_ERR)

def error_msg(path:str, *msg:Any) -> str:
  return f'muck error: {path}: ' + ''.join(str(m) for m in msg)
