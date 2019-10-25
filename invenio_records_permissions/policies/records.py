# -*- coding: utf-8 -*-
#
# Copyright (C) 2019 CERN.
# Copyright (C) 2019 Northwestern University.
#
# Invenio-Records-Permissions is free software; you can redistribute it
# and/or modify it under the terms of the MIT License; see LICENSE file for
# more details.

"""Access controls for records."""

import six
from flask import current_app
from werkzeug.utils import import_string

from ..errors import UnknownGeneratorError
from ..generators import Admin, AnyUser, AnyUserIfPublic, Deny, RecordOwners
from .base import BasePermissionPolicy


@staticmethod
def _unknwon_generator(class_name):
    raise UnknownGeneratorError("Unkown need generator class. {name}".format(
            name=class_name) + " is not one of [RecordNeedClass, NeedClass]"
    )


# TODO: This is used in various invenio-modules, so should be placed in only
#       one and reused across them
def obj_or_import_string(value, default=None):
    """Import string or return object.

    :params value: Import path or class object to instantiate.
    :params default: Default object to return if the import fails.
    :returns: The imported object.
    """
    if isinstance(value, six.string_types):
        return import_string(value)
    elif value:
        return value
    return default


class RecordPermissionPolicy(BasePermissionPolicy):
    """Access control configuration for records.

    Note that even if the array is empty, the invenio_access Permission class
    always adds the ``superuser-access``, so admins will always be allowed.
    """

    # Read access given to everyone.
    can_list = [AnyUser()]
    # Create action given to no one. Not even superusers.
    can_create = [Deny()]
    # Read access given to everyone if public record/files and owners always.
    can_read = [AnyUserIfPublic(), RecordOwners()]
    # can_read_files = [AnyUserIfPublicFiles(), RecordOwners()]
    # Update access given to record owners.
    can_update = [RecordOwners()]
    # Delete access given to admins only.
    can_delete = [Admin()]


def get_record_permission_policy():
    """Return RecordPermissionPolicy.

    Relies on ``RECORDS_PERMISSIONS_RECORD_POLICY`` to
    automatically configure functionality. This way the hoster doesn't need to
    define their own CRUD factories (functions) anymore.
    """
    return obj_or_import_string(
        current_app.config.get('RECORDS_PERMISSIONS_RECORD_POLICY'),
        default=RecordPermissionPolicy
    )
