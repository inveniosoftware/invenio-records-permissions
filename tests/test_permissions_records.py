# -*- coding: utf-8 -*-
#
# Copyright (C) 2019 CERN.
# Copyright (C) 2019 Northwestern University.
#
# Invenio-Records-Permissions is free software; you can redistribute it
# and/or modify it under the terms of the MIT License; see LICENSE file for
# more details.

from elasticsearch_dsl import Q
from flask_principal import ActionNeed, UserNeed
from invenio_access.permissions import any_user, superuser_access

# TODO: Change to from invenio_records_permissions.factories import (...)
#       If isort PR is merged:
#       https://github.com/inveniosoftware/cookiecutter-invenio-module/pull/129
from invenio_records_permissions import record_create_permission_factory, \
    record_delete_permission_factory, record_list_permission_factory, \
    record_read_permission_factory, record_update_permission_factory

# TODO: Establish record schema
record = {
    "_access": {
        "metadata_restricted": True,
        "files_restricted": True
    },
    "access_right": "restricted",
    "title": "This is a record",
    "description": "This record is a test record",
    "owners": [1, 2, 3],
    "deposits": {
        "owners": [1, 2]
    }
}


def test_record_list_permission_factory(app):
    list_perm = record_list_permission_factory()

    # Loading permissions in invenio-access always add superuser
    assert list_perm.needs == {superuser_access, any_user}
    assert list_perm.excludes == set()
    assert list_perm.query_filters == [Q('match_all')]


def test_record_create_permission_factory(app):
    create_perm = record_create_permission_factory(record)

    assert create_perm.needs == {superuser_access}
    # Fails because of bug in invenio-access:
    # https://github.com/inveniosoftware/invenio-access/issues/165
    # TODO: Fix bug, then uncomment this assertion
    # assert create_perm.excludes == {any_user}
    assert create_perm.query_filters == [~Q('match_all')]


def test_record_read_permission_factory(app, mocker):
    # Assumes identity + provides are well initialized for user
    # TODO: Integration test for g.identity.provides
    patched_g = mocker.patch('invenio_records_permissions.generators.g')
    patched_g.identity.provides = [mocker.Mock(method='id', value=1)]

    read_perm = record_read_permission_factory(record)

    assert read_perm.needs == {
        superuser_access,
        UserNeed(1),
        UserNeed(2),
        UserNeed(3)
    }
    assert read_perm.excludes == set()
    assert read_perm.query_filters == [
        Q('term', **{"_access.metadata_restricted": False}),
        Q('term', owners=1)
    ]


def test_update_permission_factory(app, mocker):
    patched_g = mocker.patch('invenio_records_permissions.generators.g')
    patched_g.identity.provides = [mocker.Mock(method='id', value=4)]

    permission = record_update_permission_factory(record)

    assert permission.needs == {
        superuser_access,
        UserNeed(1),
        UserNeed(2),
        UserNeed(3)
    }
    assert permission.excludes == set()
    assert permission.query_filters == [
        Q('term', owners=4)
    ]


def test_delete_permission_factory(app):
    permission = record_delete_permission_factory(record)

    assert permission.needs == {
        superuser_access,
        ActionNeed('admin-access')
    }
    assert permission.excludes == set()
    assert permission.query_filters == []
