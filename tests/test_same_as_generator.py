# -*- coding: utf-8 -*-
#
# Copyright (C) 2026 CESNET z.s.p.o.
#
# Invenio-Records-Permissions is free software; you can redistribute it
# and/or modify it under the terms of the MIT License; see LICENSE file for
# more details.
"""Test SameAs generator."""

from flask_principal import Need, UserNeed
from invenio_access.permissions import any_user, authenticated_user

from invenio_records_permissions.generators import (
    AnyUser,
    AuthenticatedUser,
    Disable,
    RecordOwners,
    SameAs,
)
from invenio_records_permissions.policies.base import BasePermissionPolicy


class Policy(BasePermissionPolicy):
    can_read = [AnyUser()]
    can_update = [RecordOwners()]
    can_delete = [SameAs("can_update")]
    can_edit_files = [SameAs("can_update")]


def test_same_as_basic_delegation(app, create_record):
    """Test SameAs delegates to another permission on the policy."""

    class Policy(BasePermissionPolicy):
        can_update = [RecordOwners()]
        can_delete = [SameAs("can_update")]

    record = create_record()
    policy = Policy(action="delete", record=record)

    # can_delete uses SameAs("can_update") which uses RecordOwners()
    assert UserNeed(1) in policy.needs
    assert UserNeed(2) in policy.needs
    assert UserNeed(3) in policy.needs


def test_same_as_delegates_excludes():
    """Test SameAs correctly delegates excludes method."""

    class PolicyWithExcludes(BasePermissionPolicy):
        can_read = [Disable()]
        can_write = [SameAs("can_read")]

    policy = PolicyWithExcludes(action="write")
    assert any_user in policy.excludes


def test_same_as_delegates_query_filter(mocker):
    """Test SameAs correctly delegates query_filter method."""

    class Policy(BasePermissionPolicy):
        can_read = [AnyUser()]
        can_update = [RecordOwners()]
        can_delete = [SameAs("can_update")]
        can_edit_files = [SameAs("can_update")]

    identity = mocker.Mock(provides={Need(method="id", value=1)})
    policy = Policy(action="delete", identity=identity)

    query_filter = [qf.to_dict() for qf in policy.query_filters]
    assert query_filter == [{"term": {"owners": 1}}]


def test_same_as_multiple_delegations_same_policy(app, create_record):
    """Test multiple actions delegating to the same permission."""
    record = create_record()

    class Policy(BasePermissionPolicy):
        can_update = [RecordOwners()]
        can_delete = [SameAs("can_update")]
        can_edit_files = [SameAs("can_update")]

    # Both can_delete and can_edit_files delegate to can_update
    delete_policy = Policy(action="delete", record=record)
    edit_files_policy = Policy(action="edit_files", record=record)

    assert delete_policy.needs == edit_files_policy.needs


def test_same_as_with_inherited_policy(app, create_record):
    """Test SameAs works correctly with policy inheritance."""
    record = create_record()

    class Policy(BasePermissionPolicy):
        can_update = [RecordOwners()]
        can_delete = [SameAs("can_update")]
        can_edit_files = [SameAs("can_update")]

    class InheritedPolicy(Policy):
        can_update = [AuthenticatedUser()]

    policy = InheritedPolicy(action="delete", record=record)

    # can_delete delegates to can_update, which is overridden to AuthenticatedUser()
    assert authenticated_user in policy.needs
    assert UserNeed(1) not in policy.needs
    assert UserNeed(2) not in policy.needs
    assert UserNeed(3) not in policy.needs


def test_same_as_chain_delegation(app, create_record):
    """Test SameAs can delegate to another SameAs (chain delegation)."""
    record = create_record()

    class Policy(BasePermissionPolicy):
        can_update = [RecordOwners()]
        can_delete = [SameAs("can_update")]
        can_publish = [SameAs("can_delete")]

    policy = Policy(action="publish", record=record)

    # can_publish -> can_delete -> can_update -> RecordOwners() + AuthenticatedUser()
    assert UserNeed(1) in policy.needs
    assert UserNeed(2) in policy.needs
    assert UserNeed(3) in policy.needs


def test_same_as_add_single_generator():
    """Test SameAs + single generator returns list."""
    result = SameAs("can_read") + RecordOwners()

    assert isinstance(result, list)
    assert len(result) == 2
    assert isinstance(result[0], SameAs)
    assert isinstance(result[1], RecordOwners)


def test_same_as_add_list_of_generators():
    """Test SameAs + list of generators returns combined list."""
    result = SameAs("can_read") + [RecordOwners(), AnyUser()]

    assert isinstance(result, list)
    assert len(result) == 3
    assert isinstance(result[0], SameAs)
    assert isinstance(result[1], RecordOwners)
    assert isinstance(result[2], AnyUser)


def test_same_as_list():
    """Test that SameAs can be an iterable returning itself."""
    result = SameAs("can_read")

    assert next(iter(result)) == result


def test_same_as_list_in_permission(create_record):
    """Test that SameAs can be used in a permission policy and is iterable."""
    record = create_record()

    class Policy(BasePermissionPolicy):
        can_update = [RecordOwners()]
        can_delete = SameAs("can_update")

    policy = Policy(action="delete", record=record)

    # The needs property should be able to iterate over the SameAs generator
    needs = list(policy.needs)
    assert UserNeed(1) in needs
    assert UserNeed(2) in needs
    assert UserNeed(3) in needs
