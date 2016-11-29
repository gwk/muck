import muck
import zipfile
import csv
import leather
import matplotlib.pyplot as plt

from io import BytesIO, TextIOWrapper
from pithy.io import *

csvfile = "API_NY.GDP.MKTP.CD_DS2_en_csv_v2.csv"

# Return a read handle for each of the files inside zip file
def load_zipcsv(file):
  f = open(file.name, 'rb')
  dataZip = zipfile.ZipFile(f)
  return {f: TextIOWrapper(dataZip.open(f)) for f in dataZip.namelist()}

muck.add_loader('.zip', load_zipcsv)
data = muck.load_url("http://api.worldbank.org/v2/en/indicator/NY.GDP.MKTP.CD?downloadformat=csv", ".zip")

# print(data[csvfile])

#Get the relevant row (Sub-Saharan) to plot
#Better to output to file and source from there
for id, row in enumerate(data[csvfile]):
  if id == 4:
    x = row
  if id == 219:
    y = row
    break

x = x.split(',')
y = y.split(',')
years = x[4:-2]

gdps = y[4:-2]

years = [int(y.strip('"')) for y in years]
gdps = [float(gdp.strip('"')) for gdp in gdps]

# outZ(zip(years, gdps))
# Writing output to file fails


# Tried Leather library, it can't handle such large data, or will have to 'shorten' data for it
# chart = leather.Chart('Line')
# chart.add_line(gdps)
# chart.to_svg('examples/charts/lines.svg')

#Plot with matplotlib
plt.title("Sub-Saharan GDP (in $)")
plt.plot(years, gdps)
plt.savefig(muck.dst_file(), format='svg')
#plt.show()
