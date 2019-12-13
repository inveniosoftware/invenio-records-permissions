# -*- coding: utf-8 -*-
#
# Copyright (C) 2019 CERN.
# Copyright (C) 2019 Northwestern University.
#
# Invenio-Records-Permissions is free software; you can redistribute it
# and/or modify it under the terms of the MIT License; see LICENSE file for
# more details.

"""Permission policies for Invenio records."""

import os

from setuptools import find_packages, setup

readme = open('README.rst').read()
history = open('CHANGES.rst').read()

sphinx_require = 'Sphinx>=1.5.1'

tests_require = [
    'check-manifest>=0.25',
    'coverage>=4.0',
    'isort>=4.3.3',
    'pydocstyle>=2.0.0',
    'pytest-cov>=2.5.1',
    'pytest-mock>=1.6.0',
    'pytest-pep8>=1.0.6',
    'pytest-invenio>=1.0.5',
    'invenio-accounts>=1.1.1,<1.2.0',
    'invenio_app>=1.2.3,<1.3.0',
    sphinx_require,
]

# Should follow inveniosoftware/invenio versions
invenio_db_version = '>=1.0.4,<1.1.0'
invenio_search_version = '>=1.2.0,<1.3.0'

extras_require = {
    'elasticsearch6': [
        'invenio-search[elasticsearch6]>={}'.format(invenio_search_version),
    ],
    'elasticsearch7': [
        'invenio-search[elasticsearch7]>={}'.format(invenio_search_version),
    ],
    'mysql': [
        'invenio-db[mysql,versioning]{}'.format(invenio_db_version),
    ],
    'postgresql': [
        'invenio-db[postgresql,versioning]{}'.format(invenio_db_version),
    ],
    'sqlite': [
        'invenio-db[versioning]{}'.format(invenio_db_version),
    ],
    'docs': [
        sphinx_require,
    ],
    'tests': tests_require,
}

extras_require['all'] = []
for name, reqs in extras_require.items():
    if name[0] == ':' or name in ('elasticsearch5', 'elasticsearch6',
                                  'elasticsearch7', 'mysql', 'postgresql',
                                  'sqlite'):
        continue
    extras_require['all'].extend(reqs)

setup_requires = [
    'Babel>=1.3',
    'pytest-runner>=3.0.0,<5',
]

install_requires = [
    'Flask-BabelEx>=0.9.3',
    'Flask-Principal>=0.4.0,<0.5.0',
    # Because of versioning policy that may admit minor incompatible (!)
    # backward change we also place an upper limit
    # https://invenio.readthedocs.io/en/latest/releases/maintenance-policy.html
    'invenio-access>=1.3.0,<1.4.0',
    'invenio-records-files>=1.2.0,<1.3.0',
    'bidict>=0.18.3'
]

packages = find_packages()


# Get the version string. Cannot be done with import!
g = {}
with open(os.path.join('invenio_records_permissions', 'version.py'), 'rt') as fp:
    exec(fp.read(), g)
    version = g['__version__']

setup(
    name='invenio-records-permissions',
    version=version,
    description=__doc__,
    long_description=readme + '\n\n' + history,
    keywords='invenio permissions',
    license='MIT',
    author='CERN',
    author_email='info@inveniosoftware.org',
    url='https://github.com/inveniosoftware/invenio-records-permissions',
    packages=packages,
    zip_safe=False,
    include_package_data=True,
    platforms='any',
    entry_points={
        'invenio_base.apps': [
            'invenio_records_permissions = invenio_records_permissions:InvenioRecordsPermissions',
        ],
        'invenio_i18n.translations': [
            'messages = invenio_records_permissions',
        ],
    },
    extras_require=extras_require,
    install_requires=install_requires,
    setup_requires=setup_requires,
    tests_require=tests_require,
    classifiers=[
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Topic :: Internet :: WWW/HTTP :: Dynamic Content',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.5',
        'Development Status :: 3 - Alpha',
    ],
)
