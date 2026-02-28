# -*- coding: utf-8 -*-
#
# Copyright (C) 2019-2023 CERN.
# Copyright (C) 2019-2020 Northwestern University.
# Copyright (C) 2024 Ubiquity Press.
# Copyright (C) 2026 CESNET z.s.p.o.
#
# Invenio-Records-Permissions is free software; you can redistribute it
# and/or modify it under the terms of the MIT License; see LICENSE file for
# more details.

"""Invenio Records Permissions Generators."""

import operator
from abc import ABC, abstractmethod
from functools import reduce
from itertools import chain

from flask import current_app
from flask_principal import UserNeed
from invenio_access import ActionRoles, ActionUsers, Permission
from invenio_access.permissions import (
    any_user,
    authenticated_user,
    superuser_access,
    system_process,
)
from invenio_search.engine import dsl


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
        """Search filters."""
        return []


class AnyUser(Generator):
    """Allows any user."""

    def needs(self, **kwargs):
        """Enabling Needs."""
        return [any_user]

    def query_filter(self, **kwargs):
        """Match all in search."""
        # TODO: Implement with new permissions metadata
        return dsl.Q("match_all")


class SystemProcess(Generator):
    """Allows system_process role."""

    def needs(self, **kwargs):
        """Enabling Needs."""
        return [system_process]

    def query_filter(self, identity=None, **kwargs):
        """Filters for current identity as system process."""
        if system_process in identity.provides:
            return dsl.Q("match_all")
        else:
            return []


class SystemProcessWithoutSuperUser(SystemProcess):
    """Allows system_process role, excluding superuser-access needs."""

    @staticmethod
    def _expand_superuser_access_action():
        """Fetch users and roles allowed for the superuser-access action."""
        roles = (
            ActionRoles.query_by_action(superuser_access).join(ActionRoles.role).all()
        )
        users = ActionUsers.query_by_action(superuser_access).all()
        return chain(roles, users)

    def excludes(self, **kwargs):
        """Preventing Needs."""
        return [role.need for role in self._expand_superuser_access_action()]


class Disable(Generator):
    """Denies ALL users including users and roles allowed to superuser-access action."""

    def excludes(self, **kwargs):
        """Preventing Needs."""
        return [any_user]

    def query_filter(self, **kwargs):
        """Match None in search."""
        return ~dsl.Q("match_all")


class RecordOwners(Generator):
    """Allows record owners."""

    def needs(self, record=None, **kwargs):
        """Enabling Needs."""
        return [UserNeed(owner) for owner in record.get("owners", [])]

    def query_filter(self, identity=None, **kwargs):
        """Filters for current identity as owner."""
        for need in identity.provides:
            if need.method == "id":
                return dsl.Q("term", owners=need.value)
        return []


class AnyUserIfPublic(Generator):
    """Allows any user if record is public.

    TODO: Revisit when dealing with files.
    """

    def needs(self, record=None, **kwargs):
        """Enabling Needs."""
        is_restricted = record and record.get("_access", {}).get(
            "metadata_restricted", False
        )
        return [any_user] if not is_restricted else []

    def excludes(self, record=None, **kwargs):
        """Preventing Needs."""
        return []

    def query_filter(self, **kwargs):
        """Filters for non-restricted records."""
        # TODO: Implement with new permissions metadata
        return dsl.Q("term", **{"_access.metadata_restricted": False})


class AuthenticatedUser(Generator):
    """Allows authenticated users."""

    def needs(self, **kwargs):
        """Enabling Needs."""
        return [authenticated_user]

    def query_filter(self, **kwargs):
        """Filters for current identity as super user."""
        # TODO: Implement with new permissions metadata
        return dsl.Q("match_all")


class AllowedByAccessLevel(Generator):
    """Allows users/roles/groups that have an appropriate access level."""

    # TODO: Implement other access levels:
    # 'metadata_reader'
    # 'files_reader'
    # 'files_curator'
    # 'superuser'
    ACTION_TO_ACCESS_LEVELS = {
        "create": [],
        "read": ["metadata_curator"],
        "update": ["metadata_curator"],
        "delete": [],
    }

    def __init__(self, action="read"):
        """Constructor."""
        self.action = action

    def needs(self, record=None, **kwargs):
        """Enabling UserNeeds for each person."""
        if not record:
            return []

        access_levels = AllowedByAccessLevel.ACTION_TO_ACCESS_LEVELS.get(
            self.action, []
        )

        # Name "identity" is used bc it correlates with flask-principal
        # identity while not being one.
        allowed_identities = chain.from_iterable(
            [
                record.get("internal", {})
                .get("access_levels", {})
                .get(access_level, [])
                for access_level in access_levels
            ]
        )

        return [
            UserNeed(identity.get("id"))
            for identity in allowed_identities
            if identity.get("scheme") == "person" and identity.get("id")
            # TODO: Implement other schemes
        ]

    def query_filter(self, identity=None, **kwargs):
        """Search filter for the current user with this generator."""
        id_need = next(
            (need for need in identity.provides if need.method == "id"), None
        )

        if not id_need:
            return []

        # To get the record in the search results, the access level must
        # have been put in the 'read' array
        read_levels = AllowedByAccessLevel.ACTION_TO_ACCESS_LEVELS.get("read", [])

        queries = [
            dsl.Q(
                "term",
                **{
                    "internal.access_levels.{}".format(access_level): {
                        "scheme": "person",
                        "id": id_need.value,
                        # TODO: Implement other schemes
                    }
                },
            )
            for access_level in read_levels
        ]

        return reduce(operator.or_, queries)


class AdminAction(Generator):
    """Generator for admin needs.

    This generator's purpose is to be used in cases where administration needs are required.
    The query filter of this generator is quite broad (match_all). Therefore, it must be used with care.
    """

    def __init__(self, action):
        """Constructor."""
        self.action = action
        super().__init__()

    def needs(self, **kwargs):
        """Enabling Needs."""
        return [self.action]

    def query_filter(self, identity=None, **kwargs):
        """Not implemented at this level."""
        permission = Permission(self.action)
        if identity and permission.allows(identity):
            return dsl.Q("match_all")
        return []


class ConditionalGenerator(Generator):
    """Generator that depends on whether a condition is true or not.

    .. code-block::python

        If...(
            then_=[...],
            else_=[...],
        )
    """

    def __init__(self, then_, else_):
        """Constructor."""
        self.then_ = then_
        self.else_ = else_

    @abstractmethod
    def _condition(self, **kwargs):
        """Condition to choose generators set."""
        raise NotImplementedError()

    def _generators(self, record, **kwargs):
        """Get the "then" or "else" generators."""
        return self.then_ if self._condition(record=record, **kwargs) else self.else_

    def needs(self, record=None, **kwargs):
        """Set of Needs granting permission."""
        needs = [
            g.needs(record=record, **kwargs) for g in self._generators(record, **kwargs)
        ]
        return set(chain.from_iterable(needs))

    def excludes(self, record=None, **kwargs):
        """Set of Needs denying permission."""
        excludes = [
            g.excludes(record=record, **kwargs)
            for g in self._generators(record, **kwargs)
        ]
        return set(chain.from_iterable(excludes))

    @staticmethod
    def _make_query(generators, **kwargs):
        """Make a query for one set of generators."""
        queries = [g.query_filter(**kwargs) for g in generators]
        queries = [q for q in queries if q]
        return reduce(operator.or_, queries) if queries else None


class IfConfig(ConditionalGenerator):
    """Config-based conditional generator."""

    def __init__(self, config_key, accept_values=None, **kwargs):
        """Initialize generator."""
        self.accept_values = accept_values or [True]
        self.config_key = config_key
        super().__init__(**kwargs)

    def _condition(self, **_):
        """Check if the config value is truthy."""
        return current_app.config.get(self.config_key) in self.accept_values


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


class CompositeGenerator(Generator, ABC):
    """Base class for generators that compose multiple generators.

    This generator implements the Composite design pattern, allowing you to combine
    multiple generators and treat them as a single generator. Subclasses must implement
    the ``_generators(**context)`` method to return the list of generators to compose.

    Behavior:
        - ``needs``: Combines (flattens) the needs from all composed generators
        - ``excludes``: Combines (flattens) the excludes from all composed generators
        - ``query_filter``: Combines query filters using OR logic (any filter matches)
    """

    @abstractmethod
    def _generators(self, **context):
        """Return the list of generators to compose.

        Must be implemented by subclasses.

        :param context: Context dictionary that may contain record, etc.
        :returns: List of Generator instances to compose
        """
        raise NotImplementedError  # pragma: no cover

    def needs(self, **context):
        """Get enabling needs from all composed generators.

        Combines needs from all generators into a single flattened list.
        """
        needs = [
            generator.needs(**context) for generator in self._generators(**context)
        ]
        return list(chain.from_iterable(needs))

    def excludes(self, **context):
        """Get preventing needs from all composed generators.

        Combines excludes from all generators into a single flattened list.
        """
        excludes = [
            generator.excludes(**context) for generator in self._generators(**context)
        ]
        return list(chain.from_iterable(excludes))

    def query_filter(self, **context):
        """Get search filters from all composed generators.

        Combines query filters from all generators using OR logic. This means a record
        matches if it satisfies ANY of the composed generator's filters.

        :returns: Combined query using OR, or match_none if no generators provide filters
        """
        generators = self._generators(**context)

        queries = [g.query_filter(**context) for g in generators]
        queries = [q for q in queries if q]
        if not queries:
            return dsl.Q("match_none")

        return reduce(operator.or_, queries) if queries else None


class SameAs(CompositeGenerator):
    """Generator that delegates permissions to another permission on the same policy.

    This generator allows you to reuse the permission configuration from one action
    for another action, promoting DRY (Don't Repeat Yourself) principles. It dynamically
    retrieves the generators from the specified permission attribute on the policy.

    This is particularly useful when:
        - Multiple actions should have identical permission requirements
        - You want permission inheritance when subclassing policies
        - You need to maintain a single source of truth for related permissions

    Example:
        .. code-block:: python

            class RecordPermissionPolicy(BasePermissionPolicy):
                can_edit = [RecordOwners(), AdminAction("admin-access")]
                can_delete = [SameAs("can_edit")]  # Delegates to can_edit
                can_create_files = [SameAs("can_edit")]  # Also delegates to can_edit

        In this example, ``can_delete`` and ``can_create_files`` will have the exact
        same permissions as ``can_edit``. If you later modify ``can_edit`` or override
        it in a subclass, the delegating permissions automatically inherit those changes.

    By virtue of operator overloading, ``SameAs`` can also be used outside of lists
    to simplify permission policies:

        .. code-block:: python

            class RecordPermissionPolicy(BasePermissionPolicy):
                can_manage = [RecordOwners(), SystemProcess()]
                can_curate = SameAs("can_manage") + [AccessGrant("edit")]
                can_delete = SameAs("can_curate")

    Note:
        The permission name must be an attribute on the policy instance and must
        contain a list of generators.
    """

    def __init__(self, permission_name):
        """Initialize the generator.

        :param permission_name: Name of the permission attribute to delegate to.
            Must be in the format "can_<action>" (e.g., "can_edit", "can_read").
            This attribute must exist on the permission policy and contain a list of generators.
        """
        self._delegated_permission_name = permission_name

    def _generators(self, **context):
        """Get the generators from the delegated permission on the policy.

        :param context: Must contain 'permission_policy' key with the policy instance
        :returns: List of generators from the delegated permission
        """
        policy = context["permission_policy"]
        return getattr(policy, self._delegated_permission_name)

    def __add__(self, other):
        """Allow adding another generator or list of generators to this SameAs generator.

        Example:
            can_delete = SameAs("can_edit") + [RecordOwners()]
        """
        if isinstance(other, (tuple, list, set)):
            return [self] + list(other)
        else:
            return [self, other]

    def __iter__(self):
        """Let the SameAs be used as the sole element inside the can_abc properties.

        Example:
            can_delete = SameAs("can_edit")
        """
        return iter([self])
