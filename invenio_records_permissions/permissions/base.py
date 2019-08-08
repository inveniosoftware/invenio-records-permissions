# -*- coding: utf-8 -*-
#
# Copyright (C) 2019 CERN.
#
# Invenio-Records-Permissions is free software; you can redistribute it
# and/or modify it under the terms of the MIT License; see LICENSE file for
# more details.

from flask import current_app
from invenio_access import Permission
from ..generators import Deny


class _PermissionConfig(object):

    # Deny all by default
    can_create = [Deny]
    can_list = [Deny]
    can_read = [Deny]
    can_update = [Deny]
    can_delete = [Deny]

    @classmethod
    def get_permission_list(cls, action):
        if action == 'create':
            return cls.can_create
        elif action == 'list':
            return cls.can_list
        elif action == 'read':
            return cls.can_read
        elif action == 'update':
            return cls.can_update
        elif action == 'delete':
            return cls.can_delete

        current_app.logger.error("Unkown action {action}.".format(
            action=action))
        return []


# Where can a property be used?
#
# |    Action   | need | excludes | query_filter |
# |-------------|------|----------|--------------|
# |    create   |   x  |     x    |              |
# |-------------|------|----------|--------------|
# |     list    |   x  |     x    |              |
# |-------------|------|----------|--------------|
# |     read    |   x  |     x    |       x      |
# |-------------|------|----------|--------------|
# | read files  |   x  |     x    |              |
# |-------------|------|----------|--------------|
# |    update   |   x  |     x    |              |
# |-------------|------|----------|--------------|
# |    delete   |   x  |     x    |              |
# |-------------|------|----------|--------------|
#


class BasePermission(Permission):

    def __init__(self, config, action):
        super(BasePermission, self).__init__()
        self.config = config
        self.permission_list = self.config.get_permission_list(action)

    @property
    def needs(self):
        # Needs caching cannot be done here, since sometimes depends on the
        # record. It must be implemented in each generator.
        needs = []
        for needs_generator in self.permission_list:
            tmp_need = needs_generator.needs()
            if tmp_need:
                needs.extend(tmp_need)
        # FIXME: Shall they be expended?
        return needs

    @property
    def excludes(self):
        # Needs caching cannot be done here, since sometimes depends on the
        # record. It must be implemented in each generator.
        excludes = []
        for excludes_generator in self.permission_list:
            tmp_exclude = excludes_generator.excludes()
            if tmp_exclude:
                excludes.extend(tmp_exclude)
        # FIXME: Shall they be expended?
        return excludes

    @property
    def query_filter(self):
        query_filters = []
        for qf_generator in self.permission_list:
            tmp_query_filter = qf_generator.query_filter()
            if tmp_query_filter:
                query_filters.append(tmp_query_filter)
        return query_filters
