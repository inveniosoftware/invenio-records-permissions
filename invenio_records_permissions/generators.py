# -*- coding: utf-8 -*-
#
# Copyright (C) 2019 CERN.
#
# Invenio-Records-Permissions is free software; you can redistribute it
# and/or modify it under the terms of the MIT License; see LICENSE file for
# more details.

import json

from elasticsearch_dsl.query import Q
from flask import g
from flask_principal import ActionNeed, UserNeed
from invenio_access.permissions import any_user
from invenio_files_rest.models import Bucket, ObjectVersion
from invenio_records_files.api import Record
from invenio_records_files.models import RecordsBuckets


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


class IfPublicRecordFactory(_RecordNeedClass):

    def __init__(self, is_restricted, es_filter):
        super(IfPublicRecordFactory, self).__init__()
        self.is_restricted = is_restricted
        self.es_filter = es_filter

    def needs(self, record, *args, **kwargs):
        if not self.is_restricted(record, *args, **kwargs):
            return [any_user]
        else:
            return None

    def excludes(self, record, *args, **kwargs):
        pass

    def query_filter(self, *args, **kwargs):
        return self.es_filter(*args, **kwargs)


def _is_restricted(record, *args, **kwargs):
    if record:
        # FIXME: this should be caster to boolean when loaded
        return json.loads(record['_access']['metadata_restricted'])

    return True  # Restrict by default


def _is_restricted_filter(*args, **kwargs):
    return Q('term', **{"_access.metadata_restricted": False})


AnyUserIfPublic = IfPublicRecordFactory(_is_restricted, _is_restricted_filter)


class _BucketNeedClass(_NeedClass):

    def __init__(self):
        super(_BucketNeedClass, self).__init__()

    def needs(self, bucket, *args, **kwargs):
        pass

    def excludes(self, bucket, *args, **kwargs):
        pass

    def query_filter(self, *args, **kwargs):
        pass


class IfPublicBucketFactory(_BucketNeedClass):

    def __init__(self, is_restricted, es_filter):
        super(IfPublicBucketFactory, self).__init__()
        self.is_restricted = is_restricted
        self.es_filter = es_filter

    def needs(self, bucket, *args, **kwargs):
        if not self.is_restricted(bucket, *args, **kwargs):
            return [any_user]
        else:
            return None

    def excludes(self, bucket, *args, **kwargs):
        pass

    def query_filter(self, *args, **kwargs):
        return self.es_filter(*args, **kwargs)


# FIXME: Adapt to the files factory
def _get_record_from_bucket(bucket_id):
    rbs = RecordsBuckets.query.filter_by(bucket_id=bucket_id).all()
    if len(rbs) >= 2:  # Extra formats bucket or bad records-buckets state
        # Only admins should access. Users use the ".../formats" endpoints
        return None
    rb = next(iter(rbs), None)  # Use first bucket
    if rb:
        return Record.get_record(rb.record_id)


def _is_files_restricted(bucket, *args, **kwargs):
    # FIXME: Its inconsistent, upon creation it receives a bucket with ``id`` field
    # In the get case the field is called ``bucket_id``.
    _record = None
    if isinstance(bucket, ObjectVersion):
        _record = _get_record_from_bucket(bucket.bucket_id)
    elif isinstance(bucket, Bucket):
        _record = _get_record_from_bucket(bucket.id)
    else:
        print(bucket.__class__.__name__)

    if _record:
        if _is_restricted(record=_record) or _record['access_right'] != 'open':
            return True

        # FIXME: this should be caster to boolean when loaded
        return json.loads(_record['_access']['files_restricted'])

    return True  # Restrict by default

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


def _is_files_restricted_filter(*args, **kwargs):
    files_restricted = Q('term', **{"_access.files_restricted": False})
    access_rights = Q('term', access_right='open')

    return _is_restricted_filter() & files_restricted & access_rights


AnyUserIfPublicFiles = IfPublicBucketFactory(
    _is_files_restricted,
    _is_files_restricted_filter
)
