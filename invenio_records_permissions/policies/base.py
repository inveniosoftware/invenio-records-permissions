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

from ..generators import Deny

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
        """List of Needs generators for self.action."""
        action = self.action
        cls = self.__class__
        if hasattr(cls, 'can_' + action):
            return getattr(cls, 'can_' + action)

        current_app.logger.error("Unknown action {action}.".format(
            action=action))

        return []

    @property
    def needs(self):
        """Set of generated Needs.

        If ANY of the Needs are matched, permission is allowed.
        """
        needs = [
            generator.needs(**self.over) for generator in self.generators
        ]
        needs = set(chain.from_iterable(needs))

        self.explicit_needs |= needs
        self._load_permissions()  # explicit_needs is used here
        return self._permissions.needs

    @property
    def excludes(self):
        """Set of excluded Needs.

        NOTE: `excludes` take precedence over `needs` i.e., if the same Need
        is in the `needs` list and the `excludes` list, then that Need is
        excluded (must not be provided by identity).
        """
        excludes = [
            generator.excludes(**self.over) for generator in self.generators
        ]
        excludes = set(chain.from_iterable(excludes))
        # self.explicit_excludes |= excludes  # See invenio_access issue
        self._load_permissions()
        return self._permissions.excludes

    @property
    def query_filters(self):
        """List of ElasticSearch query filters."""
        filters = [
            generator.query_filter(**self.over)
            for generator in self.generators
        ]
        return [f for f in filters if f]
