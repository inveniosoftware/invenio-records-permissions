# -*- coding: utf-8 -*-
#
# Copyright (C) 2019 CERN.
#
# Invenio-Records-Permissions is free software; you can redistribute it
# and/or modify it under the terms of the MIT License; see LICENSE file for
# more details.

from elasticsearch_dsl.query import Q
from invenio_access.permissions import any_user, authenticated_user
from flask_principal import UserNeed, ActionNeed


class NeedClass(object):

    def needs(self):
        pass

    def excludes(self):
        pass

    def query_filter(self):
        pass


class _AnyUser(NeedClass):

    def __init__(self):
        super(_AnyUser, self).__init__()

    def needs(self):
        yield any_user


AnyUser = _AnyUser()


class _Deny(NeedClass):

    def __init__(self):
        super(_Deny, self).__init__()

    def excludes(self):
        yield any_user


Deny = _Deny()


class _Admin(NeedClass):

    def __init__(self):
        super(_Admin, self).__init__()

    def needs(self):
        yield ActionNeed('admin-access')


Admin = _Admin()


class RecordNeedClass(NeedClass):

    def __init__(self):
        super(RecordNeedClass, self).__init__()

    def needs(self, record):
        pass

    def excludes(self, record):
        pass

    def query_filter(self, user):
        pass


class _RecordOwners(RecordNeedClass):

    def __init__(self):
        super(_RecordOwners, self).__init__()

    def needs(self, record):
        if record:
            for owner in record.get('owners', []):
                yield UserNeed(owner)

    # def query_filter(self, user):
    #     return Q('term', owner=user.get_id())


RecordOwners = _RecordOwners()


class _DepositOwners(RecordNeedClass):

    def __init__(self):
        super(_DepositOwners, self).__init__()

    def needs(self, record):
        for owner in record.get('deposits', {}).get('owners', []):
            yield UserNeed(owner)


DepositOwners = _DepositOwners()


class IfPublicFactory(RecordNeedClass):

    def __init__(self, is_restricted, es_filter):
        super(IfPublicFactory, self).__init__()
        self.is_restricted = is_restricted
        self.es_filter = es_filter

    def needs(self, record):
        if record:
            if not self.is_restricted(record):
                yield any_user
        # FIXME: Do this distinction? or a different generator for listing?
        # If the record is None, its a ``list`` operation
        # The filter is created by the ``query_filter`` function.
        else:
            yield any_user

    def query_filter(self, *args):
        return self.es_filter(*args)


def _is_restricted(record):
    return record['_access']['metadata_restricted']


def _is_restricted_filter(*args):
    return Q('term', **{"_access.metadata_restricted": False})


AnyUserIfPublic = IfPublicFactory(_is_restricted, _is_restricted_filter)


def _is_files_restricted(record=None):
    if _is_restricted(record) or record['access_right'] != 'open':
        return True
    return record['_access']['files_restricted']


AnyUserIfPublicFiles = IfPublicFactory(
    _is_files_restricted,
    _is_restricted_filter  # FIXME: For testing, need to translate the other one.
)
