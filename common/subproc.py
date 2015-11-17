# Dedicated to the public domain under CC0: https://creativecommons.org/publicdomain/zero/1.0/ by George King.

import shlex as _shlex
import subprocess as _sp


PIPE = _sp.PIPE


class NULL:
  def __new__(cls):
    raise TypeError('NULL is an opaque singleton value; do not instantiate.')


class SubprocessExpectation(Exception):
  def __init__(self, cmd, label, exp, act):
    super().__init__('expected subprocess {} {} {}; received: {}'.format(
      cmd, label, exp, act))


_null_file = None
def _special_or_file(f):
  '''
  return the file, unless it is a special marker, in which case:
    - NULL: return opened /dev/null (reused).
  '''
  global _null_file
  if f is NULL:
    if _null_file is None:
      _null_file = open('/dev/null', 'r+b') # read/write binary
    return _null_file
  return f


def _decode(s):
  return s if s is None else s.decode('utf-8')


def run_cmd(cmd, cwd, stdin, out, err, env, exp):
  '''
  run a command and return (exit_code, std_out, std_err).
  the underlying Subprocess shell option is not supported
  because the rules regarding splitting strings are complex.
  user code is made clearer by just specifying the complete sh command,
  which is always split by shlex.split.
  '''
  if isinstance(cmd, str):
    cmd = _shlex.split(cmd)

  if isinstance(stdin, str):
    f_in = PIPE
    input_bytes = stdin.encode('utf-8')
  elif isinstance(stdin, bytes):
    f_in = PIPE
    input_bytes = stdin
  else:
    f_in = _special_or_file(stdin) # presume None, file, PIPE, or NULL.
    input_bytes = None

  p = _sp.Popen(
    cmd,
    cwd=cwd,
    stdin=f_in,
    stdout=_special_or_file(out),
    stderr=_special_or_file(err),
    shell=False,
    env=env
  )
  p_out, p_err = p.communicate(input_bytes)

  c = p.returncode
  if exp is None:
    pass
  elif isinstance(exp, bool):
    if bool(c) != exp:
      raise SubprocessExpectation(cmd, 'to return code', exp, c)
  else: # expect exact numeric code.
    if c != exp:
      raise SubprocessExpectation(cmd, 'to return code', exp, c)

  return c, _decode(p_out), _decode(p_err)


def runCOE(cmd, cwd=None, stdin=None, env=None, exp=0):
  return run_cmd(cmd, cwd, stdin, PIPE, PIPE, env, exp)


def runC(cmd, cwd=None, stdin=None, out=None, err=None, env=None, exp=None):
  'run a command and return exit code.'
  assert out is not PIPE
  assert err is not PIPE
  c, o, e = run_cmd(cmd, cwd, stdin, out, err, env, exp)
  assert o is None
  assert e is None
  return c


def runCO(cmd, cwd=None, stdin=None, err=None, env=None, exp=None):
  'run a command and return exit code, std out.'
  assert err is not PIPE
  c, o, e = run_cmd(cmd, cwd, stdin, PIPE, err, env, exp)
  assert e is None
  return c, o



def runCE(cmd, cwd=None, stdin=None, out=None, env=None, exp=None):
  'run a command and return exit code, std err.'
  assert out is not PIPE
  c, o, e = run_cmd(cmd, cwd, stdin, out, PIPE, env, exp)
  assert o is None
  return c, e


def runOE(cmd, cwd=None, stdin=None, env=None, exp=0):
  'run a command and return (stdout, stderr) as strings.'
  c, o, e = run_cmd(cmd, cwd, stdin, PIPE, PIPE, env, exp)
  return o, e


def runO(cmd, cwd=None, stdin=None, err=None, env=None, exp=0):
  'run a command and return stdout as a string.'
  assert err is not PIPE
  c, o, e = run_cmd(cmd, cwd, stdin, PIPE, err, env, exp)
  assert e is None
  return o


def runE(cmd, cwd=None, stdin=None, out=None, env=None, exp=0):
  'run a command and return stderr as a string.'
  assert out is not PIPE
  c, o, e = run_cmd(cmd, cwd, stdin, out, PIPE, env, exp)
  assert o is None
  return e
