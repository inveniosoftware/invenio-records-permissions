# -*- coding: utf-8 -*-
#
# Copyright (C) 2019 CERN.
# Copyright (C) 2019 Northwestern University.
#
# Invenio-Records-Permissions is free software; you can redistribute it
# and/or modify it under the terms of the MIT License; see LICENSE file for
# more details.

"""Pytest configuration.

See https://pytest-invenio.readthedocs.io/ for documentation on which test
fixtures are available.
"""

from __future__ import absolute_import, print_function

import shutil
import tempfile

import pytest
from flask import Flask
from flask_babelex import Babel
from invenio_access import InvenioAccess
from invenio_accounts import InvenioAccounts
from invenio_db import InvenioDB
from invenio_search import InvenioSearch

from invenio_records_permissions import InvenioRecordsPermissions


@pytest.fixture(scope='module')
def celery_config():
    """Override pytest-invenio fixture.

    TODO: Remove this fixture if you add Celery support.
    """
    return {}


@pytest.fixture(scope='module')
def create_app(instance_path):
    """Application factory fixture."""
    def factory(**config):
        app = Flask('testapp', instance_path=instance_path)
        app.config.update(**config)
        Babel(app)
        InvenioAccess(app)
        InvenioAccounts(app)
        InvenioDB(app)
        InvenioRecordsPermissions(app)
        InvenioSearch(app)
        return app
    return factory


@pytest.fixture(scope="session")
def create_record():
    """Factory pattern for a loaded Record.

    The returned dict record has the interface of a Record.

    It provides a default value for each required field.
    """
    def _create_record(metadata=None):
        # TODO: Modify according to record schema
        metadata = metadata or {}
        record = {
            "_access": {
                # TODO: Remove if "access_right" includes it
                "metadata_restricted": False,
                "files_restricted": False
            },
            "access_right": "open",
            "title": "This is a record",
            "description": "This record is a test record",
            "owners": [1, 2, 3],
            "deposits": {
                "owners": [1, 2]
            },
            "sys": {
                "permissions": {},
            }
        }
        record.update(metadata)
        return record

    return _create_record
