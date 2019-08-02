# -*- coding: utf-8 -*-
#
# Copyright (C) 2019 CERN.
#
# Invenio-Records-Permissions is free software; you can redistribute it
# and/or modify it under the terms of the MIT License; see LICENSE file for
# more details.

from flask import current_app
from werkzeug.utils import import_string

from ..generators import Admin, AnyUserIfPublic, AnyUserIfPublicFiles, Deny, \
    _NeedClass, _RecordNeedClass, RecordOwners
from .base import BasePermission, _PermissionConfig

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
def record_list_permission_factory(record=None):
    # FIXME: Permanent None for the ``record`` to the RecordPermission?
    return RecordPermission(_Config.config(), 'list', record)


def record_create_permission_factory(record=None):
    return RecordPermission(_Config.config(), 'create', record)


def record_read_permission_factory(record=None):
    return RecordPermission(_Config.config(), 'read', record)


def record_read_files_permission_factory(record=None, *args):
    return RecordPermission(_Config.config(), 'read_files', record)


def record_update_permission_factory(record=None):
    return RecordPermission(_Config.config(), 'update', record)


def record_delete_permission_factory(record=None):
    return RecordPermission(_Config.config(), 'delete', record)


@staticmethod
def _log_unknwon_generator(class_name):
    current_app.logger.error("Unkown need generator class. {name}".format(
            name=class_name) + " is not one of [RecordNeedClass, NeedClass]"
    )


class RecordPermissionConfig(_PermissionConfig):
    """Access control configuration for records.

    Note that even if the array is empty, the invenio_access Permission class
    always adds the ``superuser-access``, so admins will always be allowed.

    - Create action given to no one.
    - Read access given to everyone.
    - Update access given to record owners.
    - Delete access given to admins only.
    """
    can_list = [AnyUser]
    can_create = [Deny]
    can_read = [AnyUserIfPublic, RecordOwners]
    # FIXME: Need to refactor the files perm factory
    # It need to handle the reception of (bucket, action) instead of a record
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

    def __init__(self, config=RecordPermissionConfig, action=None, record=None):
        super(RecordPermission, self).__init__(config, action)
        self.record = record

    @property
    def needs(self):
        needs = []
        for needs_generator in self.permission_list:
            tmp_needs = None
            if isinstance(needs_generator, _RecordNeedClass):
                tmp_needs = needs_generator.needs(self.record)
            elif isinstance(needs_generator, _NeedClass):
                tmp_needs = needs_generator.needs()
            else:
                # FIXME: Shall it raise and complain?
                _log_unknwon_generator(type(needs_generator).__name__)

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
            elif isinstance(needs_generator, _NeedClass):
                tmp_excludes = needs_generator.excludes()
            else:
                # FIXME: Shall it raise and complain?
                _log_unknwon_generator(type(needs_generator).__name__)

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
                # FIXME: Shall it raise and complain?
                _log_unknwon_generator(type(qf_generator).__name__)

            if tmp_query_filter:
                query_filters.append(tmp_query_filter)

        return query_filters
