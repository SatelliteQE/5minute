
from setuptools import setup, find_packages
# To use a consistent encoding
from codecs import open
from os import path

here = path.abspath(path.dirname(__file__))

# Get the long description from the README file
with open(path.join(here, 'README.rst'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='vminute',
    version='0.1',
    description='A tool for quick creation and deployment of Openstack machines used for QA testing.',
    long_description=long_description,
    # FIXME Enter correct github url, not just url made-up from the thin air.
    url='https://github.com/vminute',
    author='Martin Korbel',
    author_email='mkorbel@redhat.com',
    license='Apache Software License',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Information Technology',
        'Topic :: Software Development :: Quality Assurance',
        'License :: OSI Approved :: Apache Software License',
    ],
    keywords='openstack testing deployment',
    install_requires=['python-keystoneclient',
                      'python-cinderclient',
                      'python-heatclient',
                      'python-neutronclient',
                      'python-novaclient',
                      'xmltodict',
                      'lprettytable'],
    packages=find_packages(),
    package_data={
        'vminute': ['scenarios/README']
    },
    entry_points={
        'console_scripts': [
            'vminute=vminute:main_main'
        ]
    }
)
