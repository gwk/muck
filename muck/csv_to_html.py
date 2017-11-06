#!/usr/bin/env python3
# Dedicated to the public domain under CC0: https://creativecommons.org/publicdomain/zero/1.0/.

'''
Generate an HTML table from CSV.
'''

import csv
import sys
from html import escape as html_esc


def main() -> None:
  _, path = sys.argv
  with open(path, newline='') as f:
    print('<table>')
    reader = csv.reader(f)
    try: header = next(reader)
    except StopIteration:
      print('</table>')
      return
    print('<thead><tr>', end='')
    for cell in header:
      print('<th>', html_esc(cell), '</th>', sep='', end='')
    print('</tr></thead>')
    print('<tbody>')
    for row in reader:
      print('<tr>', end='')
      for cell in row:
        print('<td>', html_esc(cell), '</td>', sep='', end='')
      print('</tr>')
    print('</tbody></table>')


if __name__ == '__main__': main()
