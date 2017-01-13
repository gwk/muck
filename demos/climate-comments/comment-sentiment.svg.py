import muck
from collections import Counter
from textblob import TextBlob
from pithy.csv_utils import *
from pithy.io import *
from hearts import *


rows = muck.load('comment-counts.json')
sentiments = Counter()
for comment_count, comment in rows:
  blob = TextBlob(comment)
  polarity = blob.sentiment.polarity
  sentiments[round(polarity * 20)] += 1

chart = Chart(title='Comment Sentiment Histogram',
  axes=[Axis('Sentiment Score (20ths)'), Axis('# of Comments')])

errP(sentiments)
chart.add(Bars(sentiments.items()))
outZ(chart.to_svg())

