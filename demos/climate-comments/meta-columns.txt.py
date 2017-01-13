import muck
from pithy.json_utils import *
from pithy.io import *

meta = muck.load('raw-meta.json')
columns = meta['view']['columns']
outL([c['fieldName'] for c in columns])

