import muck
import zipfile
import csv
import leather
import matplotlib.pyplot as plt
from io import TextIOWrapper

# CSV file containing the required data
csvfile = "API_NY.GDP.MKTP.KD.ZG_DS2_en_csv_v2.csv"

# Returns a dictionary of {filename : read handle} for all files inside the zip file. 
def load_zipcsv(zipFile):
  f = open(zipFile.name, 'rb')
  dataZip = zipfile.ZipFile(f)
  return {f: TextIOWrapper(dataZip.open(f)) for f in dataZip.namelist()}

muck.add_loader('.zip', load_zipcsv)
data = muck.load_url("http://api.worldbank.org/v2/en/indicator/NY.GDP.MKTP.KD.ZG?downloadformat=csv", ".zip")

# Get the relevant rows to plot
# Row 4 is the Years
# Row 219 is the of Sub-Saharan Africa GDP growth (annual %)"
# Columns 45 to -3 will be the years 2001 to 2015 
for i, row in enumerate(data[csvfile]):
  if i == 4:
    years = row.split(',')[45:-2]
    years = [int(year.strip('"')) for year in years]
  if i == 219:
    gdps = row.split(',')[45:-2]
    gdps = [float(gdp.strip('"')) for gdp in gdps]
    break

# Tried Leather library, it doesn't handle large data gracefully. 
# But it suffices here as we are plotting a small number of data points
# and renders a better 'looking' graph than matplotlib as well. 
chart = leather.Chart('Sub-Saharan Africa annual GDP growth (annual %)')
chart.add_line(list(zip(years,gdps)))
chart.to_svg(muck.dst_file())

# Uncomment below lines to plot with matplotlib
# plt.title("Sub-Saharan Africa annual GDP growth")
# plt.plot(years, gdps)
# plt.savefig(muck.dst_file(), format='svg')

# NOTE: Observed some discrepencies b/w the graph we get by plotting the World Bank data and the one in the article here
# http://qz.com/806292/imf-sub-saharan-africas-gdp-economic-growth-will-fall-to-its-worst-level-in-two-decades/Year-to-year 
# 1. Quartz have used the IMF projection for 2016 as the data point for 2016.
# 2. I see many values have changed, (Ex: Year 2004). Perhaps, the World Bank data has been updated. 
