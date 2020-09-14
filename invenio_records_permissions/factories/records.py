# -*- coding: utf-8 -*-
#
# Copyright (C) 2019-2020 CERN.
# Copyright (C) 2019-2020 Northwestern University.
#
# Invenio-Records-Permissions is free software; you can redistribute it
# and/or modify it under the terms of the MIT License; see LICENSE file for
# more details.

"""Record Permission Factories."""

from invenio_records.api import Record

from ..policies import get_record_permission_policy


def record_search_permission_factory(record=None):
    """Pre-configured record search permission factory."""
    PermissionPolicy = get_record_permission_policy()
    return PermissionPolicy(action='search')


def record_create_permission_factory(record=None):
    """Pre-configured record create permission factory."""
    PermissionPolicy = get_record_permission_policy()
    return PermissionPolicy(action='create', record=record)


def record_read_permission_factory(record=None):
    """Pre-configured record read permission factory."""
    PermissionPolicy = get_record_permission_policy()
    return PermissionPolicy(action='read', record=record)


def record_update_permission_factory(record=None):
    """Pre-configured record update permission factory."""
    PermissionPolicy = get_record_permission_policy()
    return PermissionPolicy(action='update', record=record)


def record_delete_permission_factory(record=None):
    """Pre-configured record delete permission factory."""
    PermissionPolicy = get_record_permission_policy()
    return PermissionPolicy(action='delete', record=record)
