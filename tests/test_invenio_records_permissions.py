# -*- coding: utf-8 -*-
#
# Copyright (C) 2019 CERN.
# Copyright (C) 2019 Northwestern University.
#
# Invenio-Records-Permissions is free software; you can redistribute it
# and/or modify it under the terms of the MIT License; see LICENSE file for
# more details.

"""Module tests."""

from __future__ import absolute_import, print_function

from flask import Flask

from invenio_records_permissions import InvenioRecordsPermissions


def test_version():
    """Test version import."""
    from invenio_records_permissions import __version__
    assert __version__


def test_init():
    """Test extension initialization."""
    app = Flask('testapp')
    ext = InvenioRecordsPermissions(app)
    assert 'invenio-records-permissions' in app.extensions

    app = Flask('testapp')
    ext = InvenioRecordsPermissions()
    assert 'invenio-records-permissions' not in app.extensions
    ext.init_app(app)
    assert 'invenio-records-permissions' in app.extensions
