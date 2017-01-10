# Dedicated to the public domain under CC0: https://creativecommons.org/publicdomain/zero/1.0/.

from setuptools import setup


name = 'muck'

setup(
  name=name,
  version='0.0.3',
  license='CC0',
  author='George King',
  author_email='george.w.king@gmail.com',
  url='https://github.com/gwk/' + name,
  description='Muck is a build tool for data projects that automatically calculates dependencies.',
  packages=[name, name + '.pithy'],
  entry_points = {'console_scripts': [
    'muck=muck.__main__:main',
  ]},
  install_requires=[
    'requests',
  ],
  keywords=[
    'build tool', 'data science',
  ],
  classifiers=[ # See https://pypi.python.org/pypi?%3Aaction=list_classifiers.
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
