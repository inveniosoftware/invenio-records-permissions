# -*- coding: utf-8 -*-
#
# Copyright (C) 2019 CERN.
# Copyright (C) 2019 Northwestern University.
#
# Invenio-Records-Permissions is free software; you can redistribute it
# and/or modify it under the terms of the MIT License; see LICENSE file for
# more details.

"""Permission policies for Invenio records."""

from __future__ import absolute_import, print_function

from .ext import InvenioRecordsPermissions
from .factories import record_create_permission_factory, \
    record_delete_permission_factory, record_files_permission_factory, \
    record_list_permission_factory, record_read_permission_factory, \
    record_update_permission_factory
from .policies import BasePermissionPolicy, DepositPermissionPolicy, \
    RecordPermissionPolicy
from .version import __version__

__all__ = (
    '__version__',
    'BasePermissionPolicy',
    'DepositPermissionPolicy',
    'InvenioRecordsPermissions',
    'RecordPermissionPolicy',
    # TODO: Hide behind invenio_records_permissions.factories
    # if isort PR is merged:
    # https://github.com/inveniosoftware/cookiecutter-invenio-module/pull/129
    'record_create_permission_factory',
    'record_delete_permission_factory',
    'record_files_permission_factory',
    'record_list_permission_factory',
    'record_read_permission_factory',
    'record_update_permission_factory',
)
