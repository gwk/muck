import muck
from collections import *
from pithy.json_utils import *
from pithy.io import *

data = muck.load('raw-data.json')

counter = Counter()
for record in data:
  ( sid, id, position, created_at, created_meta, updated_at, updated_meta,
    meta, name, affiliation, home_town, state_or_country, comment, attachment) = record
  counter[comment] += 1

out_json(sorted([(count, comment) for (comment, count) in counter.items()], reverse=True))
