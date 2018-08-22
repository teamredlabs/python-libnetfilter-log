"""The setup.py script."""

from distutils.core import setup, Extension

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
      ext_modules=[Extension(
          name="libnetfilterlog",
          sources=["libnetfilterlog.c"],
          libraries=["netfilter_log", "nfnetlink"]
      )])
