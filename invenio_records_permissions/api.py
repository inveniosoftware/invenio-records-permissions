# -*- coding: utf-8 -*-
#
# Copyright (C) 2019-2020 CERN.
# Copyright (C) 2019-2020 Northwestern University.
#
# Invenio-Records-Permissions is free software; you can redistribute it
# and/or modify it under the terms of the MIT License; see LICENSE file for
# more details.

"""Invenio Records Permissions API."""

from elasticsearch_dsl.query import Q


def records_permission_filter(permission):
    """Records permission filter."""
    # NOTE: flask-principal overwrites __bool() and access g
    if permission is not None:
        qf = None
        for f in permission.query_filters:
            qf = qf | f if qf else f
        return qf
    else:
        return Q()
