# -*- coding: utf-8 -*-
#
# Copyright (C) 2019 CERN.
# Copyright (C) 2019 Northwestern University.
#
# Invenio App RDM is free software; you can redistribute it and/or modify it
# under the terms of the MIT License; see LICENSE file for more details.

"""Invenio Records Permissions API."""

from elasticsearch_dsl.query import Q
from flask import current_app
from invenio_search.api import DefaultFilter, RecordsSearch


def rdm_records_filter():
    """Records filter."""
    # TODO: Implement with new permissions metadata
    perm_factory = current_app.config['RECORDS_REST_ENDPOINTS']['recid']['read_permission_factory_imp']()  # noqa
    # FIXME: this might fail if factory returns None, meaning no "query_filter"
    # was implemente in the generators. However, IfPublic should always be
    # there.

    filters = perm_factory.query_filters
    if filters:
        qf = None
        for f in filters:
            qf = qf | f if qf else f
        return qf
    else:
        return Q()


# TODO: Move this to invenio-rdm-records and
#       * have it provide the permissions OR
#       * rely on app's current_search for tests
class RecordsSearch(RecordsSearch):
    """Search class for RDM records."""

    class Meta:
        """Default index and filter for frontpage search."""

        index = 'records'
        doc_types = None
        default_filter = DefaultFilter(rdm_records_filter)
