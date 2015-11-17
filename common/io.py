# Dedicated to the public domain under CC0: https://creativecommons.org/publicdomain/zero/1.0/ by George King.

import pprint as _pp
import string as _string
import sys as _sys

from sys import stdout, stderr


def fmt_template(template, **substitutions):
  'render a template using $ syntax.'
  t = _string.Template(template)
  return t.substitute(substitutions)


pretty_formatter = _pp.PrettyPrinter(stream=None, indent=2)

# return a formatted string representing item
def pretty_format(item):
  'return a pretty formatted string.'
  return pretty_formatter.pformat(item)


# basic printing.

def write(file, *items, sep='', end=''):
  "write items to file; sep='', end=''."
  print(*items, sep=sep, end=end, file=file)

def writeS(file, *items):
  "write items to file; sep=' ', end=''."
  print(*items, sep=' ', end='', file=file)

def writeSS(file, *items):
  "write items to file; sep=' ', end=''."
  print(*items, sep=' ', end=' ', file=file)

def writeL(file, *items, sep=''):
  "write items to file; sep='', end='\\n'."
  print(*items, sep=sep, end='\n', file=file)

def writeSL(file, *items):
  "write items to file; sep=' ', end='\\n'."
  print(*items, sep=' ', end='\n', file=file)

def writeLL(file, *items):
  "write items to file; sep='\\n', end='\\n'."
  print(*items, sep='\n', end='\n', file=file)


def writeLSSL(file, *items):
  "write items to file; sep='\\n  ', end='\\n'."
  print(*items, sep='\n  ', end='\n', file=file)


# format printing.

def writeF(file, fmt, *items, **keyed_items):
  "write the formatted string to file; end=''."
  print(fmt.format(*items, **keyed_items), end='', file=file)

def writeFL(file, fmt, *items, **keyed_items):
  "write the formatted string to file; end='\\n'."
  print(fmt.format(*items, **keyed_items), end='\n', file=file)


# templated format printing.

def writeTF(file, template_fmt, *items, **keyed_items):
  """
  expand the format string with keyed_items, then format the string; end=''.
  useful for constructing dynamic format strings.
  """
  fmt = fmt_template(template_fmt, **keyed_items)
  writeF(file, fmt, *items, **keyed_items)

def writeTFL(file, template_fmt, *items, **keyed_items):
  """
  expand the format string template with keyed_items, then format the string; end='\\n'
  useful for constructing dynamic format strings.
  """
  fmt = fmt_template(template_fmt, **keyed_items)
  writeFL(file, fmt, *items, **keyed_items)


def writeP(file, *items, label=None):
  'pretty print to file.'
  if label is not None:
    file.write(label)
    file.write (': ')
  for i in items:
    file.write(pretty_format(i))
    file.write('\n')


# std out.

def out(*items, sep='', end=''):
  "write items to std out; sep='', end=''."
  print(*items, sep=sep, end=end)

def outS(*items):
  "write items to std out; sep=' ', end=''."
  print(*items, end='')

def outSS(*items):
  "write items to std out; sep=' ', end=' '."
  print(*items, end=' ')

def outL(*items, sep=''):
  "write items to std out; sep='', end='\\n'."
  print(*items, sep=sep)

def outSL(*items):
  "write items to std out; sep=' ', end='\\n'."
  print(*items)

def outLL(*items):
  "write items to std out; sep='\\n', end='\\n'."
  print(*items, sep='\n')

def outLSSL(*items):
  "write items to std out; sep='\\n  ', end='\\n'."
  print(*items, sep='\n  ')

def outF(fmt, *items, **keyed_items):
  "write the formatted string to std out; end=''."
  writeF(stdout, fmt, *items, **keyed_items)

def outFL(fmt, *items, **keyed_items):
  "write the formatted string to std out; end='\\n'."
  writeFL(stdout, fmt, *items, **keyed_items)

def outP(*items, label=None):
  'pretty print to std out.'
  writeP(stdout, *items, label=label)


# std err.

def log(*items, sep='', end=''):
  "write items to std err; sep='', end=''."
  print(*items, sep=sep, end=end, file=stderr)

def logS(*items):
  "write items to std err; sep=' ', end=''."
  print(*items, sep=' ', end='', file=stderr)

def logSS(*items):
  "write items to std err; sep=' ', end=''."
  print(*items, sep=' ', end=' ', file=stderr)

def logL(*items, sep=''):
  "write items to std err; sep='', end='\\n'."
  print(*items, sep=sep, end='\n', file=stderr)

def logSL(*items):
  "write items to std err; sep=' ', end='\\n'."
  print(*items, sep=' ', end='\n', file=stderr)

def logLL(*items):
  "write items to std err; sep='\\n', end='\\n'."
  print(*items, sep='\n', end='\n', file=stderr)

def logLSSL(*items):
  "write items to std err; sep='\\n  ', end='\\n'."
  print(*items, sep='\n  ', end='\n', file=stderr)

def logF(fmt, *items, **keyed_items):
  "write the formatted string to std err; end=''."
  writeF(stderr, fmt, *items, **keyed_items)

def logFL(fmt, *items, **keyed_items):
  "write the formatted string to std err; end='\\n'."
  writeFL(stderr, fmt, *items, **keyed_items)

def logP(*items, label=None):
  'pretty print to std err.'
  writeP(stderr, *items, label=label)


# errors.

def fail(*items, sep=''):
  log(*items, sep=sep, end='\n')
  _sys.exit(1)

def failS(*items): 
  fail(*items, sep=' ')

def failL(*items):
  fail(*items, sep='\n')

def failF(fmt, *items, **keyed_items):
  fail(fmt.format(*items, **keyed_items))


def check(condition, *items, sep=''):
  'if condition is False, raise an exception, joining the item arguments.'
  if not condition: fail(*items, sep=sep)

def checkS(condition, *items):
  if not condition: failS(*items)

def checkF(condition, fmt, *items, **keyed_items):
  if not condition: failF(fmt, *items, **keyed_items)


# exceptions.

def raiseS(*items, T=Exception):
  raise T(' '.join(items))

def raiseF(fmt, *items, T=Exception):
  raise T(fmt.format(*items))


def req_type(object, class_info):
  if not isinstance(object, class_info):
    raise TypeError('expected type: {}; actual type: {};\n  object: {}'.format(
      class_info, type(object), repr(object)))

