# -*- coding: utf-8 -*-
#
# Copyright (C) 2026 CESNET z.s.p.o.
#
# Invenio-Records-Permissions is free software; you can redistribute it
# and/or modify it under the terms of the MIT License; see LICENSE file for
# more details.
"""Test CompositeGenerator."""

import json

from flask_principal import Need
from invenio_access.permissions import any_user, authenticated_user

from invenio_records_permissions.generators import (
    AnyUser,
    AnyUserIfPublic,
    AuthenticatedUser,
    CompositeGenerator,
    Disable,
    RecordOwners,
)


class StaticCompositeGenerator(CompositeGenerator):
    """Test implementation that returns a static list of generators."""

    def __init__(self, generators):
        """Constructor."""
        self._generator_list = generators

    def _generators(self, **context):
        """Return the static list of generators."""
        return self._generator_list


def stable_dict_sort(data):
    """Recursively sort dictionaries and lists for stable comparison.

    Dictionaries are re-created with sorted keys, and lists are sorted by their JSON representation.
    This ensures that we can compare the output of query_filter regardless
    of the order of keys in dictionaries or items in lists.

    Note: this is intended just for tests as can be slow due to the multiple
    json dumps for each comparison.
    """
    if isinstance(data, dict):
        return {k: stable_dict_sort(v) for k, v in sorted(data.items())}
    elif isinstance(data, list):
        deep_sorted = [stable_dict_sort(x) for x in data]
        return sorted(deep_sorted, key=lambda x: json.dumps(x, sort_keys=True))
    else:
        return data


def test_composite_generator_empty_list():
    """Test CompositeGenerator with empty generator list."""
    generator = StaticCompositeGenerator([])

    assert generator.needs() == []
    assert generator.excludes() == []
    assert generator.query_filter().to_dict() == {"match_none": {}}


def test_composite_generator_single_generator():
    """Test CompositeGenerator with a single generator."""
    generator = StaticCompositeGenerator([AnyUser()])

    assert generator.needs() == [any_user]
    assert generator.excludes() == []
    assert generator.query_filter().to_dict() == {"match_all": {}}


def test_composite_generator_multiple_generators_needs(create_record):
    """Test CompositeGenerator combines needs from multiple generators."""
    from flask_principal import UserNeed

    record = create_record()
    generator = StaticCompositeGenerator([AnyUser(), RecordOwners()])

    needs = generator.needs(record=record)
    assert any_user in needs
    assert UserNeed(1) in needs
    assert UserNeed(2) in needs
    assert UserNeed(3) in needs
    assert len(needs) == 4


def test_composite_generator_multiple_generators_excludes():
    """Test CompositeGenerator combines excludes from multiple generators."""
    generator = StaticCompositeGenerator([Disable()])

    excludes = generator.excludes()
    assert excludes == [any_user]


def test_composite_generator_query_filter_or_logic(mocker):
    """Test CompositeGenerator combines query filters with OR logic."""
    generator = StaticCompositeGenerator([AnyUserIfPublic(), RecordOwners()])

    # Test with identity
    identity = mocker.Mock(provides=[Need(method="id", value=1)])
    query_filter = generator.query_filter(identity=identity)

    query_dict = query_filter.to_dict()
    assert stable_dict_sort(query_dict) == {
        "bool": {
            "should": [
                {"term": {"_access.metadata_restricted": False}},
                {"term": {"owners": 1}},
            ]
        }
    }


def test_composite_generator_query_filter_single_result():
    """Test CompositeGenerator with only one generator providing query filter."""
    generator = StaticCompositeGenerator([AnyUser()])

    query_filter = generator.query_filter()
    assert query_filter.to_dict() == {"match_all": {}}


def test_composite_generator_query_filter_all_empty(mocker):
    """Test CompositeGenerator when no generator provides query filter."""

    class EmptyFilterGenerator(AnyUser):
        def query_filter(self, **kwargs):
            return []

    generator = StaticCompositeGenerator([EmptyFilterGenerator()])
    query_filter = generator.query_filter()
    assert query_filter.to_dict() == {"match_none": {}}


def test_composite_generator_with_context(create_record):
    """Test CompositeGenerator passes context to all generators."""
    from flask_principal import UserNeed

    record = create_record()
    generator = StaticCompositeGenerator([RecordOwners(), AnyUserIfPublic()])

    needs = generator.needs(record=record)
    assert UserNeed(1) in needs
    assert UserNeed(2) in needs
    assert UserNeed(3) in needs
    assert any_user in needs


def test_composite_generator_mixed_generators(create_record, mocker):
    """Test CompositeGenerator with various generator types."""
    from flask_principal import UserNeed

    record = create_record()
    generator = StaticCompositeGenerator(
        [AnyUser(), RecordOwners(), AuthenticatedUser()]
    )

    # Test needs
    needs = generator.needs(record=record)
    assert any_user in needs
    assert authenticated_user in needs
    assert UserNeed(1) in needs
    assert UserNeed(2) in needs
    assert UserNeed(3) in needs

    # Test excludes
    excludes = generator.excludes(record=record)
    assert excludes == []
