# -*- coding: utf-8 -*-
#
# Copyright (C) 2019 CERN.
# Copyright (C) 2019 Northwestern University.
# Copyright (C) 2023 Graz University of Technology
#
# Invenio-Records-Permissions is free software; you can redistribute it
# and/or modify it under the terms of the MIT License; see LICENSE file for
# more details.

import copy

import pytest
from flask_principal import ActionNeed, Need, UserNeed
from invenio_access.permissions import any_user, authenticated_user, system_process
from invenio_search.engine import dsl

from invenio_records_permissions.generators import (
    AllowedByAccessLevel,
    AnyUser,
    AnyUserIfPublic,
    AuthenticatedUser,
    ConditionalGenerator,
    Disable,
    Generator,
    IfConfig,
    RecordOwners,
    SystemProcess,
    SystemProcessWithoutSuperUser,
)


def test_generator():
    generator = Generator()

    assert generator.needs() == []
    assert generator.excludes() == []
    assert generator.query_filter() == []


def test_any_user():
    generator = AnyUser()

    assert generator.needs() == [any_user]
    assert generator.excludes() == []
    assert generator.query_filter().to_dict() == {"match_all": {}}


def test_disable():
    generator = Disable()

    assert generator.needs() == []
    assert generator.excludes() == [any_user]
    assert generator.query_filter().to_dict() in [
        {"match_none": {}},
    ]


def _test_system_process_query_filter(generator, mocker):
    # Anonymous identity.
    assert not generator.query_filter(identity=mocker.Mock(provides=[]))

    # Authenticated user identity
    assert not generator.query_filter(
        identity=mocker.Mock(provides=[Need(method="id", value=1)])
    )

    # System process identity
    query_filter = generator.query_filter(
        identity=mocker.Mock(provides=[system_process])
    )
    assert query_filter.to_dict() == {"match_all": {}}


def test_system_process(mocker):
    generator = SystemProcess()

    assert generator.needs() == [system_process]
    assert generator.excludes() == []
    _test_system_process_query_filter(generator, mocker)


def test_system_process_without_superuser(mocker, role_w_superuser_access_need):
    generator = SystemProcessWithoutSuperUser()

    assert generator.needs() == [system_process]
    assert generator.excludes() == [role_w_superuser_access_need]
    _test_system_process_query_filter(generator, mocker)


def test_record_owner(create_record, mocker):
    generator = RecordOwners()
    record = create_record()

    assert generator.needs(record=record) == [UserNeed(1), UserNeed(2), UserNeed(3)]
    assert generator.excludes(record=record) == []

    # Anonymous identity.
    assert not generator.query_filter(identity=mocker.Mock(provides=[]))

    # Authenticated identity
    query_filter = generator.query_filter(
        identity=mocker.Mock(provides=[Need(method="id", value=1)])
    )
    assert query_filter.to_dict() == {"term": {"owners": 1}}


def test_any_user_if_public(create_record):
    generator = AnyUserIfPublic()
    record = create_record()
    private_record = create_record(
        {
            "_access": {"metadata_restricted": True, "files_restricted": True},
            "access_right": "restricted",
        }
    )

    assert generator.needs(record=record) == [any_user]
    assert generator.needs(record=private_record) == []

    assert generator.excludes(record=record) == []
    assert generator.excludes(record=private_record) == []

    assert generator.query_filter().to_dict() == {
        "term": {"_access.metadata_restricted": False}
    }


def test_authenticateduser():
    """Test Generator AuthenticatedUser."""
    generator = AuthenticatedUser()

    assert generator.needs() == [authenticated_user]
    assert generator.excludes() == []
    assert generator.query_filter().to_dict() == {"match_all": {}}


@pytest.mark.parametrize("action", ["read", "update", "delete"])
def test_allowedbyaccesslevels_metadata_curator(action, create_record):
    # Restricted record, only viewable by owner and a Metadata Curator
    record = create_record(
        {
            "owners": [4],
            "_access": {"metadata_restricted": True, "files_restricted": True},
            "internal": {
                "access_levels": {"metadata_curator": [{"scheme": "person", "id": 1}]}
            },
        }
    )
    generator = AllowedByAccessLevel(action=action)

    if action in ["read", "update"]:
        assert generator.needs(record=record) == [UserNeed(1)]
    else:
        assert generator.needs(record=record) == []

    assert generator.excludes(record=record) == []


def test_allowedbyaccesslevels_query_filter(mocker):
    # TODO: Test query_filter on the actual search engine instance per #23

    # User that has been allowed
    generator = AllowedByAccessLevel()
    query_filter = generator.query_filter(
        identity=mocker.Mock(provides=[mocker.Mock(method="id", value=1)])
    )

    # TODO: Update to account for other 'read' access levels
    assert query_filter.to_dict() == {
        "term": {
            "internal.access_levels.metadata_curator": {"scheme": "person", "id": 1}
        }
    }

    # User that doesn't provide 'id'
    generator = AllowedByAccessLevel()
    query_filter = generator.query_filter(
        identity=mocker.Mock(provides=[mocker.Mock(method="foo", value=1)])
    )

    assert query_filter == []


def test_conditional(create_record, mocker):
    """Test ConditionalGenerator."""

    class ConditionalAccessGenerator(ConditionalGenerator):
        def __init__(self, then_, else_, value):
            """Constructor."""
            self.then_ = then_
            self.else_ = else_
            self._value = value

        def _condition(self, record=None, **kwargs):
            """Condition to choose generators set."""
            return record and record.get("access_right") == self._value

    public_record = create_record({"access_right": "open"})
    restricted_record = create_record({"access_right": "restricted"})
    system_record = create_record({"access_right": "system"})

    public_generator = ConditionalAccessGenerator(
        then_=[AnyUser()], else_=[RecordOwners()], value="open"
    )
    nested_generator = ConditionalAccessGenerator(
        then_=[SystemProcessWithoutSuperUser()],
        else_=[public_generator],
        value="system",
    )

    # Then, Else check
    assert public_generator.needs(record=public_record) == {any_user}
    assert public_generator.needs(record=restricted_record) == {
        UserNeed(1),
        UserNeed(2),
        UserNeed(3),
    }

    # Nesting conditional generators
    assert nested_generator.needs(record=public_record) == {any_user}
    assert nested_generator.needs(record=restricted_record) == {
        UserNeed(1),
        UserNeed(2),
        UserNeed(3),
    }
    assert nested_generator.needs(record=system_record) == {system_process}

    # excludes
    generator = ConditionalAccessGenerator(
        then_=[Disable()], else_=[AnyUser()], value="system"
    )
    assert generator.excludes(record=system_record) == {any_user}
    assert generator.excludes(record=public_record) == set()

    # make_query
    # Or will reduce to the most open clause
    assert ConditionalGenerator._make_query(
        generators=[AnyUser(), AnyUserIfPublic()]
    ) == dsl.Q("match_all")
    assert ConditionalGenerator._make_query(
        generators=[AnyUserIfPublic(), RecordOwners()],
        identity=mocker.Mock(provides=[Need(method="id", value=1)]),
    ) == dsl.Q(
        "bool",
        should=[
            dsl.Q("term", **{"_access.metadata_restricted": False}),
            dsl.Q("term", **{"owners": 1}),
        ],
    )


def test_ifconfig(app, create_record):
    """Test IfConfig generator."""

    r = create_record()
    config_name = "IFCONFIG_TEST"
    app.config[config_name] = True

    generator = IfConfig(config_name, then_=[AnyUser()], else_=[RecordOwners()])
    assert generator.needs(record=r) == {any_user}

    app.config[config_name] = False
    assert generator.needs(record=r) == {
        UserNeed(1),
        UserNeed(2),
        UserNeed(3),
    }
