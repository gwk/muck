# Dedicated to the public domain under CC0: https://creativecommons.org/publicdomain/zero/1.0/.

# distutils setup script.
# users should install with: `$ pip3 install muck`
# developers can make a local install with: `$ pip3 install -e .`
# upload to pypi test server with: `$ py3 setup.py sdist upload -r pypitest`
# upload to pypi prod server with: `$ py3 setup.py sdist upload`

from setuptools import setup


long_description = '''\
Muck is a build tool; given a target (a file to be built), it looks in the current directory for a source file with a matching name, determines its dependencies, recursively builds those, and then finally builds the target. Unlike traditional build systems such as Make, Muck determines the dependencies of a given file by analyzing the file source; there is no 'makefile'. This means that Muck is limited to source languages that it understands, and to source code written to respect Muck's limitations. In addition to understanding code dependencies (e.g. Python import statements), Muck also provides several input functions that denote data dependencies, principly the `source` function. This allows data transformation projects to be organized as a series of dependent steps; Muck will cache build results for both code and data, allowing for efficient, iterative development. See readme.wu for documentation.
'''

setup(
  name='muck',
  license='CC0',
  version='0.0.0',
  author='George King',
  author_email='george.w.king@gmail.com',
  url='https://github.com/gwk/muck',
  description='Muck is a build tool that automatically calculates dependencies.',
  long_description=long_description,
  install_requires=['pat-tool', 'pithy', 'writeup-tool'],
  packages=['muck'],
  entry_points = { 'console_scripts': [
    'muck=muck.__main__:main',
  ]},
  keywords=['documentation', 'markup'],
  classifiers=[ # See https://pypi.python.org/pypi?%3Aaction=list_classifiers
    'Development Status :: 3 - Alpha',
    'Environment :: Console',
    'Intended Audience :: Developers',
    'Intended Audience :: Education',
    'Intended Audience :: Information Technology',
    'Intended Audience :: Science/Research',
    'License :: CC0 1.0 Universal (CC0 1.0) Public Domain Dedication',
    'Programming Language :: Python :: 3 :: Only',
    'Topic :: Documentation',
    'Topic :: Education',
    'Topic :: Internet',
    'Topic :: Multimedia',
    'Topic :: Software Development',
    'Topic :: Software Development :: Build Tools',
    'Topic :: Software Development :: Documentation',
    'Topic :: Text Processing',
    'Topic :: Text Processing :: Markup',
    'Topic :: Text Processing :: Markup :: HTML',
  ],
)
