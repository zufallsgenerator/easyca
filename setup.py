# -*- coding: utf-8 -*-

import sys
from setuptools import (
    setup,
    find_packages
)

from setuptools.command.test import test as TestCommand


def parse_reqs(path):
    lines = []
    with open(path) as f:
        for raw_l in f.readlines():
            l = raw_l.strip()
            if l and not l.startswith("#"):
                lines.append(l)
    return lines


class PyTest(TestCommand):
    user_options = [('pytest-args=', 'a', "Arguments to pass to pytest")]

    def initialize_options(self):
        TestCommand.initialize_options(self)
        self.pytest_args = ''

    def run(self):
        import shlex
        # import here, cause outside the eggs aren't loaded
        import pytest
        errno = pytest.main(shlex.split(self.pytest_args))
        sys.exit(errno)


with open('README.rst') as f:
    readme = f.read()

with open('LICENSE') as f:
    license = f.read()

reqs = parse_reqs('requirements.txt')


setup(
    name='easyca',
    version='0.1.0',
    description='Helper for creating SSL CAs and signing certificates',
    long_description=readme,
    author='Christer Byström',
    author_email='zool79@gmail.com',
    url='https://github.com/zufallsgenerator/easyca',
    license=license,
    install_requires=reqs,
    packages=find_packages(exclude=('tests', 'docs')),
    tests_require=['pytest'],
    cmdclass = {'test': PyTest},
)
