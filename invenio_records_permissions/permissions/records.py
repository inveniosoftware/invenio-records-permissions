# -*- coding: utf-8 -*-
#
# Copyright (C) 2019 CERN.
#
# Invenio-Records-Permissions is free software; you can redistribute it
# and/or modify it under the terms of the MIT License; see LICENSE file for
# more details.

from flask import current_app
from werkzeug.utils import import_string

from .base import BasePermission, _PermissionConfig
from ..errors import UnknownGeneratorError
from ..generators import Admin, AnyUserIfPublic, AnyUserIfPublicFiles, \
    _BucketNeedClass, Deny, _NeedClass, _RecordNeedClass, RecordOwners

# REMOVE
from ..generators import AnyUser
####


class _Config(object):

    _config = None

    @classmethod
    def config(cls):
        if not cls._config:
            class_name = current_app.config.get(
                'RECORDS_PERMISSIONS_RECORD_FACTORY'
            )
            if class_name:
                cls._config = import_string(class_name)
            else:
                cls._config = RecordPermissionConfig
        return cls._config


# Record factories
def record_list_permission_factory(*args, **kwargs):
    return RecordPermission(action='list', config=_Config.config())


def record_create_permission_factory(record=None):
    return RecordPermission(
        action='create',
        config=_Config.config(),
        record=record
    )


def record_read_permission_factory(record=None):
    return RecordPermission(
        action='read',
        config=_Config.config(),
        record=record
    )


def record_read_files_permission_factory(bucket=None, *args):
    return RecordPermission(
        action='read_files',
        config=_Config.config(),
        bucket=bucket
    )


def record_update_permission_factory(record=None):
    return RecordPermission(
        action='update',
        config=_Config.config(),
        record=record
    )


def record_delete_permission_factory(record=None):
    return RecordPermission(
        action='delete',
        config=_Config.config(),
        record=record
    )


@staticmethod
def _unknwon_generator(class_name):
    raise UnknownGeneratorError("Unkown need generator class. {name}".format(
            name=class_name) + " is not one of [RecordNeedClass, NeedClass]"
    )


class RecordPermissionConfig(_PermissionConfig):
    """Access control configuration for records.

    Note that even if the array is empty, the invenio_access Permission class
    always adds the ``superuser-access``, so admins will always be allowed.

    - Create action given to no one. Not even superusers. To achieve this
      behaviour you need to define a ``Superuser`` need generator.
    - Read access given to everyone.
    - Update access given to record owners.
    - Delete access given to admins only.
    """
    can_list = [AnyUser]
    can_create = [Deny]
    can_read = [AnyUserIfPublic, RecordOwners]
    can_read_files = [AnyUserIfPublicFiles, RecordOwners]
    can_update = [RecordOwners]
    can_delete = [Admin]

    @classmethod
    def get_permission_list(cls, action):
        if action == 'create':
            return cls.can_create
        elif action == 'list':
            return cls.can_list
        elif action == 'read':
            return cls.can_read
        elif action == 'read_files':
            return cls.can_read_files
        elif action == 'update':
            return cls.can_update
        elif action == 'delete':
            return cls.can_delete

        current_app.logger.error("Unkown action {action}.".format(
            action=action))
        return []


class RecordPermission(BasePermission):

    def __init__(self, action, config=RecordPermissionConfig, record=None,
                 bucket=None):
        super(RecordPermission, self).__init__(config, action)
        self.record = record
        self.bucket = bucket

    @property
    def needs(self):
        needs = []
        for needs_generator in self.permission_list:
            tmp_needs = None
            if isinstance(needs_generator, _RecordNeedClass):
                tmp_needs = needs_generator.needs(self.record)
            elif isinstance(needs_generator, _BucketNeedClass):
                tmp_needs = needs_generator.needs(self.bucket)
            elif isinstance(needs_generator, _NeedClass):
                tmp_needs = needs_generator.needs()
            else:
                _unknwon_generator(type(needs_generator).__name__)

            if tmp_needs:
                needs.extend(tmp_needs)

        self.explicit_needs = self.explicit_needs.union(needs)
        self._load_permissions()

        return self._permissions.needs

    @property
    def excludes(self):
        excludes = []
        for needs_generator in self.permission_list:
            tmp_excludes = None
            if isinstance(needs_generator, _RecordNeedClass):
                tmp_excludes = needs_generator.excludes(self.record)
            elif isinstance(needs_generator, _BucketNeedClass):
                tmp_excludes = needs_generator.needs(self.bucket)
            elif isinstance(needs_generator, _NeedClass):
                tmp_excludes = needs_generator.excludes()
            else:
                _unknwon_generator(type(needs_generator).__name__)

            if tmp_excludes:
                excludes.extend(tmp_excludes)

        self.explicit_needs = self.explicit_needs.union(excludes)
        self._load_permissions()

        return self._permissions.excludes

    @property
    def query_filter(self):
        query_filters = []
        for qf_generator in self.permission_list:
            tmp_query_filter = None
            if isinstance(qf_generator, _RecordNeedClass):
                tmp_query_filter = qf_generator.query_filter()
            elif isinstance(qf_generator, _NeedClass):
                tmp_query_filter = qf_generator.query_filter()
            else:
                _unknwon_generator(type(qf_generator).__name__)

            if tmp_query_filter:
                query_filters.append(tmp_query_filter)

        return query_filters
