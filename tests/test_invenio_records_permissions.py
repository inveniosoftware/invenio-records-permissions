# SPDX-FileCopyrightText: 2019 CERN.
# SPDX-FileCopyrightText: 2019 Northwestern University.
# SPDX-License-Identifier: MIT

"""Module tests."""

from flask import Flask

from invenio_records_permissions import InvenioRecordsPermissions


def test_version():
    """Test version import."""
    from invenio_records_permissions import __version__

    assert __version__


def test_init():
    """Test extension initialization."""
    app = Flask("testapp")
    ext = InvenioRecordsPermissions(app)
    assert "invenio-records-permissions" in app.extensions

    app = Flask("testapp")
    ext = InvenioRecordsPermissions()
    assert "invenio-records-permissions" not in app.extensions
    ext.init_app(app)
    assert "invenio-records-permissions" in app.extensions
