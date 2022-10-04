# -*- coding: utf-8 -*-
#
# Copyright (C) 2022 CERN.
#
# Invenio-Records-Permissions is free software; you can redistribute it
# and/or modify it under the terms of the MIT License; see LICENSE file for
# more details.
from flask_principal import ActionNeed, Need, UserNeed
from invenio_access.permissions import any_user, system_process

from invenio_records_permissions import RecordPermissionPolicy


def test_delete_record_policy(role_w_superuser_access_need):
    """Test delete record policy."""
    delete_perm = RecordPermissionPolicy(action="delete")

    # only superuser can delete
    assert delete_perm.needs == {role_w_superuser_access_need}
    assert delete_perm.excludes == set()


def test_create_record_policy(role_w_superuser_access_need):
    """Test create record policy."""
    create_perm = RecordPermissionPolicy(action="create")

    # superuser role added by base policy
    assert create_perm.needs == {role_w_superuser_access_need}
    # exclude everyone - the records should be created via deposits,
    # so no one should be able to create the record directly
    assert create_perm.excludes == {any_user}


def test_update_record_policy(create_record, role_w_superuser_access_need):
    """Test create record policy."""
    record = create_record()
    update_perm = RecordPermissionPolicy(action="update", record=record)

    # only owners should be able to update
    assert update_perm.needs == {
        UserNeed(1),
        UserNeed(2),
        UserNeed(3),
        role_w_superuser_access_need,
    }
    assert update_perm.excludes == set()


def test_read_policy(create_record):
    """Test read record policy."""
    record = create_record()
    read_perm = RecordPermissionPolicy(action="read", record=record)

    # anyone and owners can read
    assert read_perm.needs == {UserNeed(1), UserNeed(2), UserNeed(3), any_user}
    assert read_perm.excludes == set()


def test_read_files_policy(create_record):
    """Test read record files policy."""
    record = create_record()
    read_perm = RecordPermissionPolicy(action="read_files", record=record)

    # anyone and owners can read
    assert read_perm.needs == {UserNeed(1), UserNeed(2), UserNeed(3), any_user}
    assert read_perm.excludes == set()


def test_update_files_policy(create_record, role_w_superuser_access_need):
    """Test update record files policy."""
    record = create_record()
    read_perm = RecordPermissionPolicy(action="update_files", record=record)

    # only owners should be able to update
    assert read_perm.needs == {
        UserNeed(1),
        UserNeed(2),
        UserNeed(3),
        role_w_superuser_access_need,
    }
    assert read_perm.excludes == set()
