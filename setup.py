from setuptools import setup, find_packages
# To use a consistent encoding
from codecs import open
from os import path
import re

here = path.abspath(path.dirname(__file__))

with open(path.join(here, 'README'), encoding='utf-8') as f:
    long_description = f.read()

with open(path.join(here, 'requirements.txt'), encoding='utf-8') as f:
    content = f.readlines()
    reqs = filter(None, [x.strip() for x in content])


def get_version():
    VERSIONFILE = path.join('5minute.spec')
    initfile_lines = open(VERSIONFILE, 'rt').readlines()
    VSRE = r"^Version:\s*([^'\"]*)\s*"
    for line in initfile_lines:
        mo = re.search(VSRE, line, re.M)
        if mo:
            return mo.group(1)
    raise RuntimeError('Unable to find version string in %s.' % (VERSIONFILE,))


setup(
    name='vminute',
    version=get_version(),
    description='A tool for quick creation and deployment of Openstack machines used for QA testing.',
    long_description=long_description,
    url='https://github.com/SatelliteQE/5minute',
    author='Martin Korbel',
    author_email='mkorbel@redhat.com',
    license='GNU General Public License v2 (GPLv2)',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Information Technology',
        'Topic :: Software Development :: Quality Assurance',
        'License :: OSI Approved :: GNU General Public License v2 (GPLv2)',
    ],
    keywords='openstack testing deployment',
    install_requires=reqs,
    packages=find_packages(),
    package_data={
        '': ['README.md']
    },
    entry_points={
        'console_scripts': [
            '5minute=vminute:main_main'
        ]
    }
)
