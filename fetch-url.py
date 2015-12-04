#!/usr/bin/env python3
# Dedicated to the public domain under CC0: https://creativecommons.org/publicdomain/zero/1.0/.

import argparse
import requests
import sys

from common import io

assert(sys.version_info.major == 3) # python 2 is not supported.

arg_parser = argparse.ArgumentParser(description='fetch contents of a URL specified in a .url text file.')
arg_parser.add_argument('path', help='.url file path.')
arg_parser.add_argument('-dependency-map', nargs='?', default='' ,help='map dependency names to paths; format is "k1=v1,...,kN=vN.')
args = arg_parser.parse_args()

# TODO: deduplicate; writeup does the same thing.
dependency_map = {}
for s in args.dependency_map.split(','):
  k, p, v = s.partition('=')
  if k in dependency_map:
    fail('writeup error: dependency map has duplicate key: {}', k)
  dependency_map[k] = v

try:
  f = open(args.path)
except Exception:
  errFL('could not open path: {}', args.path)
  raise

url = f.read().strip()
r = requests.get(url)

if r.status_code != 200:
  fail('fetch failed with HTTP code: {}', r.status_code)

print(r.text)
