# -*- coding: utf-8 -*-
#
# Copyright (C) 2019 CERN.
#
# Invenio-Records-Permissions is free software; you can redistribute it
# and/or modify it under the terms of the MIT License; see LICENSE file for
# more details.

from elasticsearch_dsl.query import Q
from invenio_access.permissions import any_user
from flask import g
from flask_principal import UserNeed, ActionNeed


class _NeedClass(object):

    def needs(self):
        pass

    def excludes(self):
        pass

    def query_filter(self):
        pass


class _AnyUser(_NeedClass):

    def __init__(self):
        super(_AnyUser, self).__init__()

    def needs(self):
        return [any_user]

    def query_filter(self):
        return Q('match_all')  # match all query


AnyUser = _AnyUser()


class _Deny(_NeedClass):

    def __init__(self):
        super(_Deny, self).__init__()

    def excludes(self):
        return [any_user]

    def query_filter(self):
        return ~Q('match_all')  # Match None


Deny = _Deny()


class _Admin(_NeedClass):

    def __init__(self):
        super(_Admin, self).__init__()

    def needs(self):
        return [ActionNeed('admin-access')]


Admin = _Admin()


class _RecordNeedClass(_NeedClass):

    def __init__(self):
        super(_RecordNeedClass, self).__init__()

    def needs(self, record):
        pass

    def excludes(self, record):
        pass


class _RecordOwners(_RecordNeedClass):

    def __init__(self):
        super(_RecordOwners, self).__init__()

    def needs(self, record):
        owner_needs = []
        for owner in record.get('owners', []):
            owner_needs.append(UserNeed(owner))
        return owner_needs

    def query_filter(self):
        provides = g.identity.provides
        for need in provides:
            if need.method == 'id':
                return Q('term', owners=need.value)
        return None


RecordOwners = _RecordOwners()


class _DepositOwners(_RecordNeedClass):

    def __init__(self):
        super(_DepositOwners, self).__init__()

    def needs(self, record):
        deposit_owners = []
        for owner in record.get('deposits', {}).get('owners', []):
            deposit_owners.append(UserNeed(owner))
        return deposit_owners

    def query_filter(self):
        provides = g.identity.provides
        for need in provides:
            if need.method == 'id':
                return Q('term', **{"deposits.owners": need.value})
        return None


DepositOwners = _DepositOwners()


class IfPublicFactory(_RecordNeedClass):

    def __init__(self, is_restricted, es_filter):
        super(IfPublicFactory, self).__init__()
        self.is_restricted = is_restricted
        self.es_filter = es_filter

    def needs(self, record):
        if not self.is_restricted(record):
            return [any_user]
        else:
            return None

    def query_filter(self, *args):
        return self.es_filter(*args)


def _is_restricted(record):
    return record['_access']['metadata_restricted']


def _is_restricted_filter(*args):
    return Q('term', **{"_access.metadata_restricted": False})


AnyUserIfPublic = IfPublicFactory(_is_restricted, _is_restricted_filter)


def _is_files_restricted(record):
    if _is_restricted(record) or record['access_right'] != 'open':
        return True
    return record['_access']['files_restricted']

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


def _is_files_restricted_filter(*args):
    files_restricted = Q('term', **{"_access.files_restricted": False})
    access_rights = Q('term', access_right='open')

    return _is_restricted_filter() & files_restricted & access_rights


AnyUserIfPublicFiles = IfPublicFactory(
    _is_files_restricted,
    _is_files_restricted_filter
)
