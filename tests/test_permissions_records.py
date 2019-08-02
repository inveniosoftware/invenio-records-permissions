# -*- coding: utf-8 -*-
#
# Copyright (C) 2019 CERN.
#
# Invenio-Records-Permissions is free software; you can redistribute it
# and/or modify it under the terms of the MIT License; see LICENSE file for
# more details.

from flask_principal import ActionNeed, UserNeed, Need
from invenio_records_permissions.permissions.records import \
    record_create_permission_factory, record_list_permission_factory, \
    record_read_permission_factory, record_update_permission_factory, \
    record_delete_permission_factory, record_read_files_permission_factory
from elasticsearch_dsl import Q

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

test_superuser_access = Need(method='action', value='superuser-access')
test_any_user = Need(method='system_role', value='any_user')


def test_record_permission(app):

    create_perm = record_create_permission_factory(record)
    list_perm = record_list_permission_factory()  # No record needed
    read_perm = record_read_permission_factory(record)
    read_files_perm = record_read_files_permission_factory(record)
    update_perm = record_update_permission_factory(record)
    delete_perm = record_delete_permission_factory(record)

    # FIXME: super user allowd but all exclude, would superuser be allowed
    assert create_perm.needs == {test_superuser_access}
    # FIXME: will fail because invenio-access adds all in 'needs'
    # https://github.com/inveniosoftware/invenio-access/blob/master/invenio_access/permissions.py#L126
    assert create_perm.excludes == {test_any_user}

    # Loading permissions in invenio-access always add superuser
    assert list_perm.needs == {test_superuser_access, test_any_user}
    assert list_perm.excludes == set()

    assert read_perm.needs == {
        test_superuser_access,
        UserNeed(1),
        UserNeed(2),
        UserNeed(3)
    }
    assert read_perm.excludes == set()
    assert read_perm.query_filter == [
        Q('term', **{"_access.metadata_restricted": False}),
        Q('term', owners=1)
    ]

    assert read_files_perm.needs == {
        test_superuser_access,
        UserNeed(1),
        UserNeed(2),
        UserNeed(3)
    }
    assert read_perm.excludes == set()
    # FIXME: read_files makes sense to query_filter?

    update_needs = update_perm.needs
    assert len(update_needs) == 3
    assert UserNeed(1) in update_needs
    assert UserNeed(2) in update_needs
    assert UserNeed(3) in update_needs
    assert update_perm.excludes == set()

    assert delete_perm.needs == {ActionNeed('admin-access')}
    assert delete_perm.excludes == set()
