# -*- coding: utf-8 -*-
#
# Copyright (C) 2019-2020 CERN.
# Copyright (C) 2019-2020 Northwestern University.
#
# Invenio-Records-Permissions is free software; you can redistribute it
# and/or modify it under the terms of the MIT License; see LICENSE file for
# more details.

"""Pytest configuration.

See https://pytest-invenio.readthedocs.io/ for documentation on which test
fixtures are available.
"""

import pytest
from flask_principal import RoleNeed
from invenio_access.models import ActionRoles
from invenio_access.permissions import superuser_access
from invenio_accounts.models import Role
from invenio_app.factory import create_app as _create_app
from invenio_records.api import Record


@pytest.fixture(scope="module")
def celery_config():
    """Override pytest-invenio fixture.

    TODO: Remove this fixture if you add Celery support.
    """
    return {}


@pytest.fixture(scope="module")
def create_app():
    """Application factory fixture."""
    return _create_app


@pytest.fixture(scope="function")
def superusers_role(db):
    """Grant `superuser_access` action to the new role."""
    superusers = Role(name="superusers")
    db.session.add(superusers)
    db.session.add(ActionRoles.allow(superuser_access, role=superusers))
    db.session.commit()
    return superusers


@pytest.fixture(scope="function")
def superusers_role_need(superusers_role):
    """Superuser role fixture."""
    return RoleNeed(superusers_role.name)


@pytest.fixture(scope="function")
def superuser_identity(app, db, UserFixture, superusers_role):
    """Superuser identity fixture."""
    user = UserFixture(
        email="superuser@inveniosoftware.org",
        password="superuser",
    )
    user.create(app, db)
    datastore = app.extensions["security"].datastore
    datastore.add_role_to_user(user.user, superusers_role)
    db.session.commit()

    return user.identity


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
                "files_restricted": False,
            },
            "access_right": "open",
            "title": "This is a record",
            "description": "This record is a test record",
            "owners": [1, 2, 3],
            "internal": {
                "access_levels": {},
            },
        }
        record.update(metadata)
        return record

    return _create_record


@pytest.fixture(scope="function")
def create_real_record(create_record, location):
    """Factory pattern to create a real Record.

    This is needed for tests relying on database and search engine operations.
    """

    def _create_real_record(metadata=None):
        record_dict = create_record(metadata)

        record = Record.create(record_dict)

        return record
        # Flush to index and database
        # current_search.flush_and_refresh(index='*')
        # db.session.commit()

    return _create_real_record
