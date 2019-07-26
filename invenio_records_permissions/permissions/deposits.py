# -*- coding: utf-8 -*-
#
# Copyright (C) 2019 CERN.
#
# Invenio-Records-Permissions is free software; you can redistribute it
# and/or modify it under the terms of the MIT License; see LICENSE file for
# more details.

from ..generators import AnyUser, DepositOwners, GlobalCurators, \
    LocalCurators
from .base import PermissionConfig
from .records import RecordPermission

"""Access controls for deposits.

#FIXME: Crosscheck this list
- Create action given to any authenticated user.
- Read access given to deposit owners.
- Update access given to deposit owners.
- Delete access given to admins only.
"""


# Record factories
def deposit_list_permission_factory():
    return RecordPermission(DepositPermissionConfig, 'list')


def deposit_create_permission_factory():
    return RecordPermission(DepositPermissionConfig, 'create')


def deposit_read_permission_factory(record):
    return RecordPermission(DepositPermissionConfig, 'read')


def deposit_update_permission_factory(record):
    return RecordPermission(DepositPermissionConfig, 'update')


def deposit_delete_permission_factory(record):
    return RecordPermission(DepositPermissionConfig, 'delete')


class DepositPermissionConfig(PermissionConfig):

    can_list = [DepositOwners, LocalCurators]
    # FIXME: What is the purpouse of Action('deposit-create')?
    can_create = [AnyUser]
    can_read = [DepositOwners]
    can_update = [GlobalCurators, LocalCurators]
    can_delete = [GlobalCurators]
