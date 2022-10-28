# -*- coding: utf-8 -*-
#
# Copyright (C) 2019-2020 CERN.
# Copyright (C) 2019-2020 Northwestern University.
# Copyright (C) 2022-2024 TU Wien.
#
# Invenio-Records-Permissions is free software; you can redistribute it
# and/or modify it under the terms of the MIT License; see LICENSE file for
# more details.

"""Default configuration variables for invenio-records-permissions."""

RECORDS_PERMISSIONS_RECORD_POLICY = (
    "invenio_records_permissions.policies.RecordPermissionPolicy"
)
"""PermissionPolicy for records."""

RECORDS_PERMISSIONS_READ_ONLY = False
"""Condition to trigger the ``DisableIfReadOnly`` permission generator."""
