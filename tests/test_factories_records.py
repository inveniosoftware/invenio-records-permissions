# -*- coding: utf-8 -*-
#
# Copyright (C) 2019-2020 CERN.
# Copyright (C) 2019-2020 Northwestern University.
#
# Invenio-Records-Permissions is free software; you can redistribute it
# and/or modify it under the terms of the MIT License; see LICENSE file for
# more details.

from io import BytesIO

import pytest
from elasticsearch_dsl import Q
from flask_principal import ActionNeed, UserNeed
from invenio_access.permissions import any_user, superuser_access
from invenio_files_rest.models import Bucket, ObjectVersion

# TODO: Change to from invenio_records_permissions.factories import (...)
#       If isort PR is merged:
#       https://github.com/inveniosoftware/cookiecutter-invenio-module/pull/129
from invenio_records_permissions import record_create_permission_factory, \
    record_delete_permission_factory, record_files_permission_factory, \
    record_read_permission_factory, record_search_permission_factory, \
    record_update_permission_factory


@pytest.fixture(scope="module")
def record(create_record):
    return create_record({
        "_access": {
            "metadata_restricted": True,
            "files_restricted": True
        },
        "access_right": "restricted"
    })


def test_record_search_permission_factory(app, superuser_role_need):
    search_perm = record_search_permission_factory()

    # Loading permissions in invenio-access always adds superuser
    assert search_perm.needs == {superuser_role_need, any_user}
    assert search_perm.excludes == set()
    assert search_perm.query_filters == [Q('match_all')]


def test_record_create_permission_factory(app, record, superuser_role_need):
    create_perm = record_create_permission_factory(record)

    assert create_perm.needs == {superuser_role_need}
    assert create_perm.excludes == {any_user}
    assert create_perm.query_filters == [~Q('match_all')]


def test_record_read_permission_factory(
        app, mocker, record, superuser_role_need):
    # Assumes identity + provides are well initialized for user
    # TODO: Integration test for g.identity.provides
    patched_g = mocker.patch('invenio_records_permissions.generators.g')
    patched_g.identity.provides = [mocker.Mock(method='id', value=1)]

    read_perm = record_read_permission_factory(record)

    assert read_perm.needs == {
        superuser_role_need,
        UserNeed(1),
        UserNeed(2),
        UserNeed(3)
    }
    assert read_perm.excludes == set()
    assert read_perm.query_filters == [
        Q('term', **{"_access.metadata_restricted": False}),
        Q('term', owners=1)
    ]


def test_update_permission_factory(app, mocker, record, superuser_role_need):
    patched_g = mocker.patch('invenio_records_permissions.generators.g')
    patched_g.identity.provides = [mocker.Mock(method='id', value=4)]

    permission = record_update_permission_factory(record)

    assert permission.needs == {
        superuser_role_need,
        UserNeed(1),
        UserNeed(2),
        UserNeed(3)
    }
    assert permission.excludes == set()


def test_delete_permission_factory(app, mocker, record):
    patched_g = mocker.patch('invenio_records_permissions.generators.g')
    patched_g.identity.provides = [mocker.Mock(method='id', value=4)]

    permission = record_delete_permission_factory(record)

    assert permission.needs == {
        superuser_access,
        ActionNeed('admin-access')
    }
    assert permission.excludes == set()


def test_update_files_permission_factory(
        create_real_record, superuser_role_need):
    record = create_real_record()
    bucket_id = record['_bucket']
    bucket = Bucket.get(bucket_id)
    action = 'bucket-update'

    permission = record_files_permission_factory(bucket, action)

    # Only super_user + owners
    assert permission.needs == {
        superuser_role_need,
        UserNeed(1),
        UserNeed(2),
        UserNeed(3)
    }
    assert permission.excludes == set()
    assert permission.action == 'update_files'


def test_read_files_permission_factory(
        create_real_record, db, superuser_role_need):
    record = create_real_record()
    bucket_id = record['_bucket']
    # TODO: Wait for repetition before making this a fixture
    a_file = BytesIO(b"file content")
    file_obj = ObjectVersion.create(bucket_id, "example.txt", stream=a_file)
    db.session.commit()
    action = 'object-read'

    permission = record_files_permission_factory(file_obj, action)

    # any_user + super_user + owners
    assert permission.needs == {
        superuser_role_need,
        any_user,
        UserNeed(1),
        UserNeed(2),
        UserNeed(3)
    }
    assert permission.excludes == set()
    assert permission.action == 'read_files'
