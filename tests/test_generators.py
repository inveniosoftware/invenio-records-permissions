# -*- coding: utf-8 -*-
#
# Copyright (C) 2019 CERN.
# Copyright (C) 2019 Northwestern University.
#
# Invenio-Records-Permissions is free software; you can redistribute it
# and/or modify it under the terms of the MIT License; see LICENSE file for
# more details.

import copy

import pytest
from flask_principal import ActionNeed, UserNeed
from invenio_access.permissions import any_user, authenticated_user

from invenio_records_permissions.generators import (
    Admin,
    AllowedByAccessLevel,
    AnyUser,
    AnyUserIfPublic,
    AuthenticatedUser,
    Disable,
    Generator,
    RecordOwners,
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


def test_admin():
    generator = Admin()

    assert generator.needs() == [ActionNeed("admin-access")]
    assert generator.excludes() == []
    assert generator.query_filter() == []


def test_record_owner(create_record, mocker):
    generator = RecordOwners()
    record = create_record()

    assert generator.needs(record=record) == [UserNeed(1), UserNeed(2), UserNeed(3)]
    assert generator.excludes(record=record) == []

    # Anonymous identity.
    assert not generator.query_filter(identity=mocker.Mock(provides=[]))

    # Authenticated identity
    query_filter = generator.query_filter(
        identity=mocker.Mock(provides=[mocker.Mock(method="id", value=1)])
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
