"""The setup.py script."""

import os

from setuptools import setup, Extension
from setuptools.command.build_py import build_py


class libnetfilter_build_py(build_py):

    def run(self):
        build_py.run(self)
        dest = os.path.join(
            self.build_lib,
            'libnetfilterlog-stubs',
            '__init__.pyi',
        )
        self.mkpath(os.path.dirname(dest))
        self.copy_file('libnetfilterlog.pyi', dest)


setup(name="python-libnetfilter-log",
      version='0.0.1',
      description='Python wrapper for libnetfilter_log',
      author='John Lawrence M. Penafiel',
      author_email='jonh@teamredlabs.com',
      license='BSD-2-Clause',
      url='https://github.com/teamredlabs/python-libnetfilter-log',
      classifiers=['Development Status :: 4 - Beta',
                   'Environment :: Plugins',
                   'Intended Audience :: Developers',
                   'Intended Audience :: Information Technology',
                   'Intended Audience :: System Administrators',
                   'License :: OSI Approved :: BSD License',
                   'Operating System :: POSIX :: Linux',
                   'Programming Language :: C',
                   'Programming Language :: Python :: 2.7',
                   'Topic :: Communications',
                   'Topic :: Internet :: Log Analysis',
                   'Topic :: System :: Networking :: Monitoring'],
      keywords='libnetfilter libnetfilterlog netfilter nflog',
      ext_modules=[Extension(name="libnetfilterlog",
                             sources=["libnetfilterlog.c"],
                             libraries=["netfilter_log", "nfnetlink"])],
      cmdclass={'build_py': libnetfilter_build_py},
      packages=['libnetfilterlog-stubs'],
      zip_safe=False)
