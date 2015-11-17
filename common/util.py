# Dedicated to the public domain under CC0: https://creativecommons.org/publicdomain/zero/1.0/ by George King.

def plural_s(len):
  return '' if len == 1 else 's'


def set_defaults(d, defaults):
  for k, v in defaults.items():
    d.setdefault(k, v)
  return d


def memoize(sentinal):
  '''
  recursive function memoization decorator.
  results will be memoized by a key that is the tuple of all arguments.
  the sentinal is inserted into the dictionary before the call.
  thus, if the function recurses with identical arguments the sentinal will be returned to the inner calls.
  '''
  def _memoize(fn):
    class MemoDictRec(dict):

      def __call__(self, *args):
        return self[args]

      def __missing__(self, args):
        self[args] = sentinal
        res = fn(*args)
        self[args] = res
        return res

    return MemoDictRec()
  return _memoize

