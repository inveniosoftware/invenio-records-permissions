# -*- coding: utf-8 -*-
#
# Copyright (C) 2019 CERN.
# Copyright (C) 2019 Northwestern University.
#
# Invenio-Records-Permissions is free software; you can redistribute it
# and/or modify it under the terms of the MIT License; see LICENSE file for
# more details.

"""Record Permission Factories."""

from ..policies import *  # get_record_permission_policy


def record_list_permission_factory(record=None):
    """Pre-configured record list permission factory."""
    PermissionPolicy = get_record_permission_policy()
    return PermissionPolicy(action='list')


def record_create_permission_factory(record=None):
    """Pre-configured record create permission factory."""
    PermissionPolicy = get_record_permission_policy()
    return PermissionPolicy(action='create', record=record)


def record_read_permission_factory(record=None):
    """Pre-configured record read permission factory."""
    PermissionPolicy = get_record_permission_policy()
    return PermissionPolicy(action='read', record=record)


# TODO: Revisit when files permission have been discussed
# def record_read_files_permission_factory(bucket=None):
#     PermissionPolicy = get_record_permission_policy()
#     return PermissionPolicy(action='read_files', bucket=bucket)


def record_update_permission_factory(record=None):
    """Pre-configured record update permission factory."""
    PermissionPolicy = get_record_permission_policy()
    return PermissionPolicy(action='update', record=record)


def record_delete_permission_factory(record=None):
    """Pre-configured record delete permission factory."""
    PermissionPolicy = get_record_permission_policy()
    return PermissionPolicy(action='delete', record=record)
