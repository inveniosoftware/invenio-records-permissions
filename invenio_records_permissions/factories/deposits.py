# -*- coding: utf-8 -*-
#
# Copyright (C) 2019 CERN.
# Copyright (C) 2019 Northwestern University.
#
# Invenio-Records-Permissions is free software; you can redistribute it
# and/or modify it under the terms of the MIT License; see LICENSE file for
# more details.

"""Deposit Permission Factories."""

from ..policies import DepositPermissionPolicy


def deposit_list_permission_factory():
    """Pre-configured deposit list permission factory."""
    return DepositPermissionPolicy(action='list')


def deposit_create_permission_factory():
    """Pre-configured deposit create permission factory."""
    return DepositPermissionPolicy(action='create')


def deposit_read_permission_factory(record):
    """Pre-configured deposit read permission factory."""
    return DepositPermissionPolicy(action='read')


def deposit_update_permission_factory(record):
    """Pre-configured deposit update permission factory."""
    return DepositPermissionPolicy(action='update')


def deposit_delete_permission_factory(record):
    """Pre-configured deposit delete permission factory."""
    return DepositPermissionPolicy(action='delete')
