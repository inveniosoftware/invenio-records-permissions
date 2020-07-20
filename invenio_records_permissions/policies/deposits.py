# -*- coding: utf-8 -*-
#
# Copyright (C) 2019-2020 CERN.
# Copyright (C) 2019-2020 Northwestern University.
#
# Invenio-Records-Permissions is free software; you can redistribute it
# and/or modify it under the terms of the MIT License; see LICENSE file for
# more details.

"""Access controls for deposits.

#FIXME: Crosscheck this list
- Create action given to any authenticated user.
- Read access given to deposit owners.
- Update access given to deposit owners.
- Delete access given to admins only.
- Use same "get_permission_policy" pattern as records.py
"""

from ..generators import AnyUser, RecordOwners
from .base import BasePermissionPolicy


class DepositPermissionPolicy(BasePermissionPolicy):
    """Access control configuration for deposits."""

    can_search = [RecordOwners()]
    can_create = [AnyUser()]
    can_read = [RecordOwners()]
    can_update = []
    can_delete = []
