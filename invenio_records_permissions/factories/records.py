# -*- coding: utf-8 -*-
#
# Copyright (C) 2019 CERN.
# Copyright (C) 2019 Northwestern University.
#
# Invenio-Records-Permissions is free software; you can redistribute it
# and/or modify it under the terms of the MIT License; see LICENSE file for
# more details.

"""Record Permission Factories."""

from invenio_files_rest.models import Bucket, ObjectVersion
from invenio_records_files.api import Record, RecordsBuckets

from ..policies import get_record_permission_policy


def record_list_permission_factory(record=None):
    """Pre-configured record list permission factory."""
    PermissionPolicy = get_record_permission_policy()
    return PermissionPolicy(action='list')


def record_create_permission_factory(record=None):
    """Pre-configured record create permission factory."""
    PermissionPolicy = get_record_permission_policy()
    return PermissionPolicy(action='create', record=record)


def record_read_permission_factory(record=None):
    """Pre-configured record read permission factory."""
    PermissionPolicy = get_record_permission_policy()
    return PermissionPolicy(action='read', record=record)


def record_update_permission_factory(record=None):
    """Pre-configured record update permission factory."""
    PermissionPolicy = get_record_permission_policy()
    return PermissionPolicy(action='update', record=record)


def record_delete_permission_factory(record=None):
    """Pre-configured record delete permission factory."""
    PermissionPolicy = get_record_permission_policy()
    return PermissionPolicy(action='delete', record=record)


def record_files_permission_factory(obj, action):
    """Files permission factory for any action.

    :param obj: An instance of :class:`invenio_files_rest.models.Bucket`.
    :param action: The required action.
    :raises RuntimeError: If the object is unknown or no record.
    :returns: A :class:`invenio_records_permissions.policies.PermissionPolicy`
        instance.
    """
    if isinstance(obj, Bucket):
        # File creation
        bucket_id = str(obj.id)
    elif isinstance(obj, ObjectVersion):
        # File download
        bucket_id = str(obj.bucket_id)
    else:
        # TODO: Reassess if covering FileObject, MultipartObject
        #       makes sense via bucket_id = str(obj.bucket_id)
        raise RuntimeError('Unknown object')

    # Retrieve record
    # WARNING: invenio-records-files implies a one-to-one relationship
    #          between Record and Bucket, but does not enforce it
    #          "for better future" the invenio-records-files code says
    record_bucket = \
        RecordsBuckets.query.filter_by(bucket_id=bucket_id).one_or_none()
    if record_bucket:
        record_metadata = record_bucket.record
        record = Record(record_metadata.json, model=record_metadata)
    else:
        raise RuntimeError('No record')

    PermissionPolicy = get_record_permission_policy()

    return PermissionPolicy(action=action, record=record)
