# -*- coding: utf-8 -*-
#
# Copyright (C) 2019-2020 CERN.
# Copyright (C) 2019-2020 Northwestern University.
#
# Invenio-Records-Permissions is free software; you can redistribute it
# and/or modify it under the terms of the MIT License; see LICENSE file for
# more details.

"""Base access controls."""

from itertools import chain

from invenio_access import Permission
from invenio_access.permissions import superuser_access
from invenio_search.engine import dsl

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

    If `can_<self.action>`
        is not defined, no one is allowed (Disable()).
        is an empty list, only Super Users are allowed (via NOTE above).
    """

    can_search = []
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
        return getattr(self.__class__, "can_" + self.action, [Disable()])

    @property
    def needs(self):
        """Set of Needs granting permission.

        If ANY of the Needs are matched, permission is granted.

        .. note::

            ``_load_permissions()`` method from `Permission
            <https://invenio-access.readthedocs.io/en/latest/api.html
            #invenio_access.permissions.Permission>`_ adds by default the
            ``superuser_access`` Need (if tied to a User or Role) for us.
            It also expands ActionNeeds into the Users/Roles that
            provide them.
        """
        needs = [generator.needs(**self.over) for generator in self.generators]
        self.explicit_needs |= set(chain.from_iterable(needs))
        self._load_permissions()  # self.explicit_needs is used here
        return self._permissions.needs

    @property
    def excludes(self):
        """Set of Needs denying permission.

        If ANY of the Needs are matched, permission is revoked.

        .. note::

            ``_load_permissions()`` method from `Permission
            <https://invenio-access.readthedocs.io/en/latest/api.html
            #invenio_access.permissions.Permission>`_ adds by default the
            ``superuser_access`` Need (if tied to a User or Role) for us.
            It also expands ActionNeeds into the Users/Roles that
            provide them.

        If the same Need is returned by `needs` and `excludes`, then that
        Need provider is disallowed.
        """
        excludes = [generator.excludes(**self.over) for generator in self.generators]
        self.explicit_excludes |= set(chain.from_iterable(excludes))
        self._load_permissions()  # self.explicit_excludes is used here
        return self._permissions.excludes

    @property
    def query_filters(self):
        """List of search engine query filters.

        These filters consist of additive queries mapping to what the current
        user should be able to retrieve via search.
        """
        filters = [generator.query_filter(**self.over) for generator in self.generators]

        # If identity has superuser access, add match_all to filters
        superuser_permission = self._expand_action(superuser_access)
        superuser_needs = superuser_permission.needs if superuser_permission else set()
        identity = self.over.get("identity")
        identity_provides = identity.provides if identity else set()
        if superuser_needs & identity_provides:
            filters.append(dsl.Q("match_all"))

        return [f for f in filters if f]
