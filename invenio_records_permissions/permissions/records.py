# -*- coding: utf-8 -*-
#
# Copyright (C) 2019 CERN.
#
# Invenio-Records-Permissions is free software; you can redistribute it
# and/or modify it under the terms of the MIT License; see LICENSE file for
# more details.

from elasticsearch_dsl.query import Q
from flask import current_app
from flask_login import current_user

from ..generators import Admin, AnyUserIfPublic, AnyUserIfPublicFiles, Deny, \
    NeedClass, RecordNeedClass, RecordOwners
from .base import BasePermission, PermissionConfig

# REMOVE
from ..generators import AnyUser
####


# Record factories
def record_list_permission_factory(record=None):
    return RecordPermission(RecordPermissionConfig, 'list', record)


def record_create_permission_factory(record=None):
    return RecordPermission(RecordPermissionConfig, 'create', record)


def record_read_permission_factory(record=None):
    # Config and action separated to give access to the config in the
    # generators.
    return RecordPermission(RecordPermissionConfig, 'read', record)


def record_update_permission_factory(record=None):
    return RecordPermission(RecordPermissionConfig, 'update', record)


def record_delete_permission_factory(record=None):
    return RecordPermission(RecordPermissionConfig, 'delete', record)


@staticmethod
def _log_unknwon_generator(class_name):
    current_app.logger.error("Unkown need generator class. {name}".format(
            name=class_name) + " is not one of [RecordNeedClass, NeedClass]"
    )


class RecordPermission(BasePermission):

    def __init__(self, config, action, record):
        super(RecordPermission, self).__init__(config, action)
        self.record = record

    @property
    def needs(self):
        # Needs caching cannot be done here, since sometimes depends on the
        # record. It must be implemented in each generator.
        needs = set()
        for needs_generator in self.permission_list:
            tmp_needs = None
            if isinstance(needs_generator, RecordNeedClass):
                tmp_needs = needs_generator.needs(self.record)
            elif isinstance(needs_generator, NeedClass):
                tmp_needs = needs_generator.needs()
            else:
                _log_unknwon_generator(type(needs_generator).__name__)

            if tmp_needs:
                needs = needs.union(tmp_needs)

        self.explicit_needs = self.explicit_needs.union(needs)
        self._load_permissions()

        return self._permissions.needs

    @property
    def excludes(self):
        excludes = set()
        for needs_generator in self.permission_list:

            tmp_excludes = None
            if isinstance(needs_generator, RecordNeedClass):
                tmp_excludes = needs_generator.excludes(self.record)
            elif isinstance(needs_generator, NeedClass):
                tmp_excludes = needs_generator.excludes()
            else:
                # FIXME: Shall it raise and complain?
                _log_unknwon_generator(type(needs_generator).__name__)

            if tmp_excludes:
                excludes = excludes.union(tmp_excludes)

        self.explicit_needs = self.explicit_needs.union(excludes)
        self._load_permissions()

        return self._permissions.excludes

    @property
    def query_filter(self):
        query_filters = None
        for qf_generator in self.permission_list:

            tmp_qfs = None
            if isinstance(qf_generator, RecordNeedClass):
                tmp_qfs = qf_generator.query_filter(current_user)
            elif isinstance(qf_generator, NeedClass):
                tmp_qfs = qf_generator.query_filter()
            else:
                _log_unknwon_generator(type(qf_generator).__name__)
            
            # FIXME: there is no "empty" filter in order to initialize the filter to it
            # The match_all filter makes ``text`` type fail (no ``fielddata`` enabled`)
            if not query_filters:
                query_filters = tmp_qfs
            if tmp_qfs:
                query_filters = query_filters | tmp_qfs
        return query_filters


class RecordPermissionConfig(PermissionConfig):
    """Access control configuration for records.

    Note that even if the array is empty, the invenio_access Permission class
    always adds the ``superuser-access``, so admins will always be allowed.

    - Create action given to no one.
    - Read access given to everyone.
    - Update access given to record owners.
    - Delete access given to admins only.
    """
    can_list = [AnyUserIfPublic, RecordOwners]
    can_create = [AnyUser]
    can_read = [AnyUserIfPublic, RecordOwners]
    can_read_files = [AnyUserIfPublicFiles, RecordOwners]
    can_update = [RecordOwners]
    can_delete = [Admin]  # Admin is redundant here.
