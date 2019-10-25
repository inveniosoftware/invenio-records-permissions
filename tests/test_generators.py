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
from invenio_access.permissions import any_user

from invenio_records_permissions.generators import Admin, AllowedIdentities, \
    AnyUser, AnyUserIfPublic, Deny, Generator, RecordOwners


def test_generator():
    generator = Generator()

    assert generator.needs() == []
    assert generator.excludes() == []
    assert generator.query_filter() == []


def test_any_user():
    generator = AnyUser()

    assert generator.needs() == [any_user]
    assert generator.excludes() == []
    assert generator.query_filter().to_dict() == {'match_all': {}}


def test_deny():
    generator = Deny()

    assert generator.needs() == []
    assert generator.excludes() == [any_user]
    assert generator.query_filter().to_dict() in [
        # ES 6-
        {'bool': {'must_not': [{'match_all': {}}]}},
        # ES 7+
        {'match_none': {}}
    ]


def test_admin():
    generator = Admin()

    assert generator.needs() == [ActionNeed('admin-access')]
    assert generator.excludes() == []
    assert generator.query_filter() == []


def test_record_owner(create_record, mocker):
    generator = RecordOwners()
    record = create_record()

    assert generator.needs(record=record) == [
        UserNeed(1),
        UserNeed(2),
        UserNeed(3)
    ]
    assert generator.excludes(record=record) == []

    # Anonymous identity
    patched_g = mocker.patch('invenio_records_permissions.generators.g')
    patched_g.identity.provides = []

    assert not generator.query_filter()

    # Authenticated identity
    patched_g = mocker.patch('invenio_records_permissions.generators.g')
    patched_g.identity.provides = [mocker.Mock(method='id', value=1)]

    assert generator.query_filter().to_dict() == {'term': {'owners': 1}}


def test_any_user_if_public(create_record):
    generator = AnyUserIfPublic()
    record = create_record()
    private_record = create_record({
        "_access": {
            "metadata_restricted": True,
            "files_restricted": True
        },
        "access_right": "restricted"
    })

    assert generator.needs(record=record) == [any_user]
    assert generator.needs(record=private_record) == []

    assert generator.excludes(record=record) == []
    assert generator.excludes(record=private_record) == []

    assert generator.query_filter().to_dict() == {
        'term': {'access_right': "open"}
    }


@pytest.fixture()
def permissions_record(create_record):
    return create_record(
        {
            "sys": {
                "permissions": {
                    "can_read": [{"type": "person", "id": 1}],
                    "can_update": [
                        {"type": "person", "id": 2},
                        {"type": "org", "id": 1}
                    ],
                    "can_foo": []
                }
            }
        })


def test_allowed_identities_read(permissions_record, mocker):
    generator = AllowedIdentities('read')
    record = permissions_record
    # Anonymous identity
    patched_g = mocker.patch('invenio_records_permissions.generators.g')
    patched_g.identity.provides = []

    assert generator.needs(record=record) == [UserNeed(1)]
    assert generator.excludes(record=record) == []
    assert not generator.query_filter()

    # Authenticated identity
    patched_g = mocker.patch('invenio_records_permissions.generators.g')
    patched_g.identity.provides = [mocker.Mock(method='id', value=1)]

    assert generator.query_filter().to_dict() == {
        'term': {
            'sys.permissions.can_read': {'type': 'person', 'id': 1}
        }
    }


def test_allowed_identities_update(permissions_record, mocker):
    generator = AllowedIdentities('update')
    record = permissions_record
    # Authenticated identity
    patched_g = mocker.patch('invenio_records_permissions.generators.g')
    patched_g.identity.provides = [mocker.Mock(method='id', value=1)]

    assert generator.needs(record=record) == [UserNeed(2)]
    assert generator.excludes(record=record) == []
    assert generator.query_filter().to_dict() == {
        'term': {
            'sys.permissions.can_update': {'type': 'person', 'id': 1}
        }
    }


def test_allowed_identities_missing_action(permissions_record, mocker):
    generator = AllowedIdentities('delete')
    record = permissions_record
    # Authenticated identity
    patched_g = mocker.patch('invenio_records_permissions.generators.g')
    patched_g.identity.provides = [mocker.Mock(method='id', value=1)]

    assert generator.needs(record=record) == []
    assert generator.excludes(record=record) == []
    assert generator.query_filter().to_dict() == {
        'term': {
            'sys.permissions.can_delete': {'type': 'person', 'id': 1}
        }
    }


def test_allowed_identities_custom_action(permissions_record, mocker):
    # test foo (i.e. custom action + empty array)
    generator = AllowedIdentities('foo')
    record = permissions_record
    # Authenticated identity
    patched_g = mocker.patch('invenio_records_permissions.generators.g')
    patched_g.identity.provides = [mocker.Mock(method='id', value=1)]

    assert generator.needs(record=record) == []
    assert generator.excludes(record=record) == []
    assert generator.query_filter().to_dict() == {
        'term': {
            'sys.permissions.can_foo': {'type': 'person', 'id': 1}
        }
    }
