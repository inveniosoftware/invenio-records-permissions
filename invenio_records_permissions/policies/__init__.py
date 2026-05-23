# SPDX-FileCopyrightText: 2019 CERN.
# SPDX-FileCopyrightText: 2019 Northwestern University.
# SPDX-License-Identifier: MIT

"""Invenio Records Permissions Policies."""

from .base import BasePermissionPolicy
from .records import RecordPermissionPolicy, get_record_permission_policy
