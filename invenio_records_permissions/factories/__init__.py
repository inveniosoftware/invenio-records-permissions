# -*- coding: utf-8 -*-
#
# Copyright (C) 2019-2020 CERN.
# Copyright (C) 2019-2020 Northwestern University.
#
# Invenio-Records-Permissions is free software; you can redistribute it
# and/or modify it under the terms of the MIT License; see LICENSE file for
# more details.

"""Pre-configured Permission Factories."""

from .records import record_create_permission_factory, \
    record_delete_permission_factory, record_files_permission_factory, \
    record_read_permission_factory, record_search_permission_factory, \
    record_update_permission_factory
