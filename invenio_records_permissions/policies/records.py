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
from ..generators import Admin, AnyUser, AnyUserIfPublic, Disable, RecordOwners
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
    """Access control configuration for records."""

    NEED_LABEL_TO_ACTION = {
        'bucket-update': 'update_files',
        'bucket-read': 'read_files',
        'object-read': 'read_files',
    }

    # Read access given to everyone.
    can_list = [AnyUser()]
    # Create action given to no one (Not even superusers) bc Deposits should
    # be used.
    can_create = [Disable()]
    # Read access given to everyone if public record/files and owners always.
    can_read = [AnyUserIfPublic(), RecordOwners()]
    # Update access given to record owners.
    can_update = [RecordOwners()]
    # Delete access given to admins only.
    can_delete = [Admin()]
    # Associated files permissions (which are really bucket permissions)
    can_read_files = [AnyUserIfPublic(), RecordOwners()]
    can_update_files = [RecordOwners()]

    def __init__(self, action, **over):
        """Constructor."""
        self.original_action = action
        action = RecordPermissionPolicy.NEED_LABEL_TO_ACTION.get(
            action, action
        )
        super(RecordPermissionPolicy, self).__init__(action, **over)


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
