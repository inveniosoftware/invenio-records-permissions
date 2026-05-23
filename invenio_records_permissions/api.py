# SPDX-FileCopyrightText: 2019-2020 CERN.
# SPDX-FileCopyrightText: 2019-2022 Northwestern University.
# SPDX-License-Identifier: MIT

"""Invenio Records Permissions API."""

from functools import reduce

from invenio_search.engine import dsl


def permission_filter(permission):
    """Generates the Query that returns visible records from a search.

    Q() is the "match all" Query.
    """
    query_filters = permission.query_filters if permission is not None else []
    query_filters = query_filters or [dsl.Q()]
    return reduce(lambda f1, f2: f1 | f2, query_filters)
