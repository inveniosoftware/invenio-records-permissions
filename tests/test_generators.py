# -*- coding: utf-8 -*-
#
# Copyright (C) 2019 CERN.
# Copyright (C) 2019 Northwestern University.
#
# Invenio-Records-Permissions is free software; you can redistribute it
# and/or modify it under the terms of the MIT License; see LICENSE file for
# more details.

import copy

from flask_principal import ActionNeed, UserNeed
from invenio_access.permissions import any_user, superuser_access

from invenio_records_permissions.generators import Admin, AnyUser, \
    AnyUserIfPublic, Disable, Generator, RecordOwners, SuperUser


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


def test_superuser():
    generator = SuperUser()

    assert generator.needs() == [superuser_access]
    assert generator.excludes() == []
    # TODO: Test query_filter when new permissions metadata implemented


def test_disable():
    generator = Disable()

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


# TODO: Establish record schema
record = {
    "_access": {
        "metadata_restricted": False,
        "files_restricted": False
    },
    "access_right": "open",
    "title": "This is a record",
    "description": "This record is a test record",
    "owners": [1, 2, 3],
    "deposits": {
        "owners": [1, 2]
    }
}


def test_record_owner(mocker):
    generator = RecordOwners()

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


private_record = copy.deepcopy(record)
private_record["_access"] = {
    "metadata_restricted": True,
    "files_restricted": True
}
private_record["access_right"] = "restricted"


def test_any_user_if_public():
    generator = AnyUserIfPublic()

    assert generator.needs(record=record) == [any_user]
    assert generator.needs(record=private_record) == []

    assert generator.excludes(record=record) == []
    assert generator.excludes(record=private_record) == []

    assert generator.query_filter().to_dict() == {
        'term': {'_access.metadata_restricted': False}
    }
