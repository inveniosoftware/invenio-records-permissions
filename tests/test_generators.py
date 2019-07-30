# -*- coding: utf-8 -*-
#
# Copyright (C) 2019 CERN.
#
# Invenio-Records-Permissions is free software; you can redistribute it
# and/or modify it under the terms of the MIT License; see LICENSE file for
# more details.

import copy

from invenio_records_permissions.generators import Admin, AnyUser, \
    AnyUserIfPublic, AnyUserIfPublicFiles, Deny, DepositOwners, \
    IfPublicFactory, _NeedClass, _RecordNeedClass, RecordOwners
from invenio_access.permissions import any_user
from flask_principal import UserNeed, ActionNeed
from elasticsearch_dsl import Q


def test_need():

    need = _NeedClass()

    assert need.needs() is None
    assert need.excludes() is None
    assert need.query_filter() is None


def test_any_user():

    need = AnyUser

    assert need.needs() == [any_user]
    assert need.excludes() is None
    assert need.query_filter().to_dict() == {'match_all': {}}


def test_deny():

    need = Deny

    assert need.excludes() == [any_user]
    assert need.needs() is None
    assert need.query_filter().to_dict() == {'match_none': {}}


def test_admin():

    need = Admin

    assert need.needs() == [ActionNeed('admin-access')]
    assert need.excludes() is None
    assert need.query_filter() is None


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


class User(object):

    def get_id(self):
        return 1

    def is_authenticated(self):
        return True


def test_record_need():
    need = _RecordNeedClass()

    assert need.needs(record) is None
    assert need.excludes(record) is None
    assert need.query_filter(None) is None


def test_record_owner():
    need = RecordOwners

    # Needs from a record
    needs = need.needs(record)
    assert len(needs) == 3
    assert UserNeed(1) in needs
    assert UserNeed(2) in needs
    assert UserNeed(3) in needs

    # Needs when the records is none (i.e. list action)
    assert need.needs(None) is None

    assert need.excludes(record) is None
    assert need.excludes(None) is None

    assert need.query_filter(User()).to_dict() == {'term': {'owners': 1}}
    assert need.query_filter(None) is None


def test_deposit_owner():
    need = DepositOwners

    # Needs from a record
    needs = need.needs(record)
    assert len(needs) == 2
    assert UserNeed(1) in needs
    assert UserNeed(2) in needs

    # Needs when the records is none (i.e. list action)
    assert need.needs(None) is None

    assert need.excludes(record) is None
    assert need.excludes(None) is None

    assert need.query_filter(User()).to_dict() == {
        'term': {'deposits.owners': 1}
    }
    assert need.query_filter(None) is None


private_record = copy.deepcopy(record)
private_record["_access"] = {
        "metadata_restricted": True,
        "files_restricted": True
    }
private_record["access_right"] = "restricted"


def test_any_user_if_public():
    need = AnyUserIfPublic

    assert need.needs(None) == [any_user]
    assert need.needs(record) == [any_user]
    assert need.needs(private_record) is None

    assert need.excludes(None) is None
    assert need.excludes(record) is None
    assert need.excludes(private_record) is None

    assert need.query_filter().to_dict() == {
        'term': {'_access.metadata_restricted': False}
    }


private_files_record = copy.deepcopy(record)
private_files_record["_access"] = {
        "metadata_restricted": False,
        "files_restricted": True
    }
private_files_record["access_right"] = "restricted"


def test_any_user_if_public_files():
    need = AnyUserIfPublicFiles

    assert need.needs(None) == [any_user]
    assert need.needs(record) == [any_user]
    assert need.needs(private_record) is None
    assert need.needs(private_files_record) is None

    assert need.excludes(None) is None
    assert need.excludes(record) is None
    assert need.excludes(private_record) is None
    assert need.excludes(private_files_record) is None

    assert need.query_filter().to_dict() == {'bool': {
        'must': [
            {'term': {'_access.metadata_restricted': False}},
            {'term': {'_access.files_restricted': False}},
            {'term': {'access_right': 'open'}}
        ]
    }}


if_public_record = copy.deepcopy(record)
if_public_record["owners"] = [4, 5]


def test_custom_if_public():
    need = IfPublicFactory(
        lambda r: 1 in r["owners"],
        lambda *args: Q()
    )

    assert need.needs(None) == [any_user]
    assert need.needs(if_public_record) == [any_user]  # public, 1 is no owner
    assert need.needs(record) is None  # private, 1 is owner

    assert need.excludes(None) is None
    assert need.excludes(record) is None
    assert need.excludes(if_public_record) is None

    assert need.query_filter().to_dict() == {'match_all': {}}
