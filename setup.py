# Dedicated to the public domain under CC0: https://creativecommons.org/publicdomain/zero/1.0/.


import sys
if sys.version_info < (3, 6): exit('error: muck requires Python3.6 or later. Make sure to install with `pip3` or `pip3.X`.')

from os import makedirs
from os.path import dirname
from distutils import log
from distutils.dep_util import newer_group
from setuptools import setup, Extension
from setuptools.command.build_ext import build_ext

#setup(setup_requires=['pbr'], pbr=True) # TODO: declarative approach would be nice.


class BuildExtLibmuck(build_ext):

  def build_extension(self, ext):
    '''
    Custom build process for libmuck.
    This appears to be necessary because on macOS at least the standard `build_extension` outputs a shared lib
    that dyld does not recognize as a dylib.
    I do not understand what format is actually output, only that the `-dynamiclib` flag is missing,
    and that simply adding that flag to the Extension constructor results in a clang error.

    Arguably we should be using some other install process because libmuck is not a real Python extension,
    but I do not see a better alternative:
    * `build_clib` produces a static library, and thus does not help us install and locate the shared lib.
    * `data_files` does not help with the compilation step, and MANIFEST.in adds poorly documented complications.

    The normal build process is two-phase compile and link; for convenience we do a single step.
    This might be a problem if the host requires a separate linker.
    We could instead leave the compile step alone and just override the link step,
    but doing so gets further into distutils internals.
    '''

    assert ext.name == 'muck._libmuck', ext
    sources = list(ext.sources)
    ext_path = self.get_ext_fullpath(ext.name)

    # copied from distutils.command.build_ext:build_extension.
    if not (self.force or newer_group(sources, ext_path, 'newer')):
      log.debug("skipping '%s' extension (up-to-date)", ext.name)
      return
    else:
      log.info("building '%s' extension", ext.name)

    compiler = self.compiler
    # copied from distutils.unixccompiler:_compile.
    compiler_so = compiler.compiler_so
    if sys.platform == 'darwin':
      import _osx_support
      compiler_so = _osx_support.compiler_fixup(compiler_so, cc_args=[])
    makedirs(dirname(ext_path), exist_ok=True) # necessary as of 3.6, 3.7a3.
    self.spawn(compiler_so + sources + ['-dynamiclib', '-o', ext_path])


setup(
  python_requires='>=3.6',
  ext_modules=[Extension('muck._libmuck', sources=['muck/libmuck.c'])],
  cmdclass={
    'build_ext': BuildExtLibmuck,
  },
  entry_points = {'console_scripts': [
    'muck=muck.main:main',
    'csv-to-html=muck.csv_to_html:main',
  ]},
)
