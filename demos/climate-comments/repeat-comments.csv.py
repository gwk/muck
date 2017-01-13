import muck
from pithy.csv_utils import *
from pithy.io import *

rows = muck.load('comment-counts.json')
repeated = [row for row in rows if row[0] > 1]
out_csv(header=('Count', 'Comment Text'), rows=repeated)
