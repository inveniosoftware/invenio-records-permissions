# -*- coding: utf-8 -*-
#
# Copyright (C) 2019 CERN.
#
# Invenio-Records-Permissions is free software; you can redistribute it
# and/or modify it under the terms of the MIT License; see LICENSE file for
# more details.

from invenio_records_permissions.permissions.base import _PermissionConfig, \
    BasePermission
from invenio_records_permissions.generators import AnyUser, Deny
from invenio_access.permissions import any_user
from elasticsearch_dsl import Q


class TestPermissionConfig(_PermissionConfig):
    can_create = [AnyUser]
    can_list = [AnyUser]
    can_read = [AnyUser]


def test_permission_config(app):

    config = _PermissionConfig
    assert config.get_permission_list('create') == [Deny]
    assert config.get_permission_list('list') == [Deny]
    assert config.get_permission_list('read') == [Deny]
    assert config.get_permission_list('update') == [Deny]
    assert config.get_permission_list('delete') == [Deny]
    assert config.get_permission_list('random') == []


def test_custom_permission_config(app):
    config = TestPermissionConfig

    assert config.get_permission_list('create') == [AnyUser]
    assert config.get_permission_list('list') == [AnyUser]
    assert config.get_permission_list('read') == [AnyUser]
    assert config.get_permission_list('update') == [Deny]
    assert config.get_permission_list('delete') == [Deny]
    assert config.get_permission_list('random') == []


def test_base_permission():
    create_perm = BasePermission(TestPermissionConfig, 'create')
    list_perm = BasePermission(TestPermissionConfig, 'list')
    read_perm = BasePermission(TestPermissionConfig, 'read')
    update_perm = BasePermission(TestPermissionConfig, 'update')
    delete_perm = BasePermission(TestPermissionConfig, 'delete')

    assert create_perm.needs == [any_user]
    assert create_perm.excludes == []

    assert list_perm.needs == [any_user]
    assert list_perm.excludes == []

    assert read_perm.needs == [any_user]
    assert read_perm.excludes == []
    assert read_perm.query_filter == [Q('match_all')]

    assert update_perm.needs == []
    assert update_perm.excludes == [any_user]

    assert delete_perm.needs == []
    assert delete_perm.excludes == [any_user]
