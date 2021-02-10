# -*- coding: utf-8 -*-
#
# Copyright (C) 2019-2020 CERN.
# Copyright (C) 2019-2020 Northwestern University.
#
# Invenio-Records-Permissions is free software; you can redistribute it
# and/or modify it under the terms of the MIT License; see LICENSE file for
# more details.

"""Invenio Records Permissions Generators."""

import json
import operator
from functools import reduce
from itertools import chain

from elasticsearch_dsl.query import Q
from flask_principal import ActionNeed, UserNeed
from invenio_access.permissions import any_user, authenticated_user, \
    superuser_access, system_process
from invenio_records.api import Record


class Generator(object):
    """Parent class mapping the context when an action is allowed or denied.

    It does so by *generating* "needed" and "excluded" Needs. At the search
    level it implements the *query filters* to restrict the search.

    Any context inherits from this class.
    """

    def needs(self, **kwargs):
        """Enabling Needs."""
        return []

    def excludes(self, **kwargs):
        """Preventing Needs."""
        return []

    def query_filter(self, **kwargs):
        """Elasticsearch filters."""
        return []


class AnyUser(Generator):
    """Allows any user."""

    def __init__(self):
        """Constructor."""
        super(AnyUser, self).__init__()

    def needs(self, **kwargs):
        """Enabling Needs."""
        return [any_user]

    def query_filter(self, **kwargs):
        """Match all in search."""
        # TODO: Implement with new permissions metadata
        return Q('match_all')


class SuperUser(Generator):
    """Allows super users."""

    def __init__(self):
        """Constructor."""
        super(SuperUser, self).__init__()

    def needs(self, **kwargs):
        """Enabling Needs."""
        return [superuser_access]

    def query_filter(self, **kwargs):
        """Filters for current identity as super user."""
        # TODO: Implement with new permissions metadata
        return []


class SystemProcess(Generator):
    """Allows system processes."""

    def __init__(self):
        """Constructor."""
        super(SystemProcess, self).__init__()

    def needs(self, **kwargs):
        """Enabling Needs."""
        return [system_process]

    def query_filter(self, **kwargs):
        """Filters for current identity as system process."""
        # TODO: Implement with new permissions metadata
        return []


class Disable(Generator):
    """Denies ALL users including super users."""

    def __init__(self):
        """Constructor."""
        super(Disable, self).__init__()

    def excludes(self, **kwargs):
        """Preventing Needs."""
        return [any_user]

    def query_filter(self, **kwargs):
        """Match None in search."""
        return ~Q('match_all')


class Admin(Generator):
    """Allows users with admin-access (different from superuser-access)."""

    def __init__(self):
        """Constructor."""
        super(Admin, self).__init__()

    def needs(self, **kwargs):
        """Enabling Needs."""
        return [ActionNeed('admin-access')]


class RecordOwners(Generator):
    """Allows record owners."""

    def needs(self, record=None, **kwargs):
        """Enabling Needs."""
        return [UserNeed(owner) for owner in record.get('owners', [])]

    def query_filter(self, identity=None, **kwargs):
        """Filters for current identity as owner."""
        for need in identity.provides:
            if need.method == 'id':
                return Q('term', owners=need.value)
        return []


class AnyUserIfPublic(Generator):
    """Allows any user if record is public.

    TODO: Revisit when dealing with files.
    """

    def needs(self, record=None, **kwargs):
        """Enabling Needs."""
        is_restricted = (
            record and
            record.get('_access', {}).get('metadata_restricted', False)
        )
        return [any_user] if not is_restricted else []

    def excludes(self, record=None, **kwargs):
        """Preventing Needs."""
        return []

    def query_filter(self, **kwargs):
        """Filters for non-restricted records."""
        # TODO: Implement with new permissions metadata
        return Q('term', **{"_access.metadata_restricted": False})


class AuthenticatedUser(Generator):
    """Allows authenticated users."""

    def __init__(self):
        """Constructor."""
        super(AuthenticatedUser, self).__init__()

    def needs(self, **kwargs):
        """Enabling Needs."""
        return [authenticated_user]

    def query_filter(self, **kwargs):
        """Filters for current identity as super user."""
        # TODO: Implement with new permissions metadata
        return Q('match_all')


class AllowedByAccessLevel(Generator):
    """Allows users/roles/groups that have an appropriate access level."""

    # TODO: Implement other access levels:
    # 'metadata_reader'
    # 'files_reader'
    # 'files_curator'
    # 'admin'
    ACTION_TO_ACCESS_LEVELS = {
        'create': [],
        'read': ['metadata_curator'],
        'update': ['metadata_curator'],
        'delete': []
    }

    def __init__(self, action='read'):
        """Constructor."""
        self.action = action

    def needs(self, record=None, **kwargs):
        """Enabling UserNeeds for each person."""
        if not record:
            return []

        access_levels = AllowedByAccessLevel.ACTION_TO_ACCESS_LEVELS.get(
            self.action, [])

        # Name "identity" is used bc it correlates with flask-principal
        # identity while not being one.
        allowed_identities = chain.from_iterable([
            record.get('internal', {})
                  .get('access_levels', {})
                  .get(access_level, [])
            for access_level in access_levels
        ])

        return [
            UserNeed(identity.get('id')) for identity in allowed_identities
            if identity.get('scheme') == 'person' and identity.get('id')
            # TODO: Implement other schemes
        ]

    def query_filter(self, identity=None, **kwargs):
        """Search filter for the current user with this generator."""
        id_need = next(
            (need for need in identity.provides if need.method == 'id'),
            None
        )

        if not id_need:
            return []

        # To get the record in the search results, the access level must
        # have been put in the 'read' array
        read_levels = AllowedByAccessLevel.ACTION_TO_ACCESS_LEVELS.get(
            'read', [])

        queries = [
            Q('term', **{
                "internal.access_levels.{}".format(access_level): {
                    "scheme": "person", "id": id_need.value
                    # TODO: Implement other schemes
                }
            }) for access_level in read_levels
        ]

        return reduce(operator.or_, queries)

#
# | Meta Restricted | Files Restricted | Access Right | Result |
# |-----------------|------------------|--------------|--------|
# |       True      |       True       |   Not Open   |  False |
# |-----------------|------------------|--------------|--------|
# |       True      |       True       |     Open     |  False | # Inconsistent
# |-----------------|------------------|--------------|--------|
# |       True      |       False      |   Not Open   |  False | # Inconsistent
# |-----------------|------------------|--------------|--------|
# |       True      |       False      |     Open     |  False | # Inconsistent
# |-----------------|------------------|--------------|--------|
# |       False     |       True       |   Not Open   |  False | ??Inconsistent
# |-----------------|------------------|--------------|--------|
# |       False     |       True       |     Open     |  False |
# |-----------------|------------------|--------------|--------|
# |       False     |       False      |   Not Open   |  False | # Inconsistent
# |-----------------|------------------|--------------|--------|
# |       False     |       False      |     Open     |  True  |
# |-----------------|------------------|--------------|--------|
#
