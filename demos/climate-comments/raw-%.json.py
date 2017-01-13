import muck
from pithy.json_utils import *
from pithy.io import *


_, key = argv

# see: https://catalog.data.gov/dataset/climate-change-adaptation-task-force

raw = muck.load_url('https://open.whitehouse.gov/api/views/8i76-ywi6/rows.json?accessType=DOWNLOAD')
out_json(raw[key])
