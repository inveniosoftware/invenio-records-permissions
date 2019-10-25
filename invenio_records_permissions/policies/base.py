# -*- coding: utf-8 -*-
#
# Copyright (C) 2019 CERN.
# Copyright (C) 2019 Northwestern University.
#
# Invenio-Records-Permissions is free software; you can redistribute it
# and/or modify it under the terms of the MIT License; see LICENSE file for
# more details.

"""Base access controls."""

from itertools import chain

from flask import current_app
from invenio_access import Permission

from ..generators import Disable

# Where can a property be used?
#
# |    Action   | need | excludes | query_filters |
# |-------------|------|----------|---------------|
# |    create   |   x  |     x    |               |
# |-------------|------|----------|---------------|
# |     list    |   x  |     x    |               |
# |-------------|------|----------|---------------|
# |     read    |   x  |     x    |        x      |
# |-------------|------|----------|---------------|
# | read files  |   x  |     x    | TODO: revisit |
# |-------------|------|----------|---------------|
# |    update   |   x  |     x    |               |
# |-------------|------|----------|---------------|
# |    delete   |   x  |     x    |               |
# |-------------|------|----------|---------------|
#


class BasePermissionPolicy(Permission):
    """
    BasePermissionPolicy to inherit from.

    The class defines the overall policy and the instance encapsulates the
    permissions for an *action* *over* a set of objects.

    NOTE: :method:`invenio_access.permissions.Permission._load_permissions()`
          used in :method:`needs` adds the superuser_access (if tied to a User
          or Role) for us.

    If `can_<self.action>`
        is not defined, no one is allowed (Disable()).
        is an empty list, only Super Users are allowed (via NOTE above).

    TODO: Recognize a PermissionPolicy class in other modules instead of
          individual factory functions to lessen the configuration burden.
    """

    can_list = []
    can_create = []
    can_read = []
    can_update = []
    can_delete = []

    def __init__(self, action, **over):
        """Constructor."""
        super(BasePermissionPolicy, self).__init__()
        self.action = action
        self.over = over

    @property
    def generators(self):
        """List of Needs generators for self.action.

        Defaults to Disable() if no can_<self.action> defined.
        """
        return getattr(self.__class__, 'can_' + self.action, [Disable()])

    @property
    def needs(self):
        """Set of generated Needs.

        If ANY of the Needs are matched, permission is allowed.

        Note that this will expand ActionNeeds into the Users/Roles that
        provide them via
        :method:`invenio_access.permissions.Permission._load_permissions()`
        """
        needs = [
            generator.needs(**self.over) for generator in self.generators
        ]
        self.explicit_needs |= set(chain.from_iterable(needs))
        self._load_permissions()  # self.explicit_needs is used here
        return self._permissions.needs

    @property
    def excludes(self):
        """Set of excluded Needs.

        NOTE: `excludes` take precedence over `needs` i.e., if the same Need
        is in the `needs` list and the `excludes` list, then that Need is
        excluded.
        """
        excludes = [
            generator.excludes(**self.over) for generator in self.generators
        ]
        self.explicit_excludes |= set(chain.from_iterable(excludes))
        self._load_permissions()  # self.explicit_excludes is used here
        return self._permissions.excludes

    @property
    def query_filters(self):
        """List of ElasticSearch query filters.

        These filters consist of additive queries mapping to what the current
        user should be able to retrieve via search.
        """
        filters = [
            generator.query_filter(**self.over)
            for generator in self.generators
        ]
        return [f for f in filters if f]
