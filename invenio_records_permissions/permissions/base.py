# -*- coding: utf-8 -*-
#
# Copyright (C) 2019 CERN.
#
# Invenio-Records-Permissions is free software; you can redistribute it
# and/or modify it under the terms of the MIT License; see LICENSE file for
# more details.

from elasticsearch_dsl.query import Q
from flask import current_app
from invenio_access import Permission


class PermissionConfig(object):

    # Deny all by default
    can_create = []
    can_list = []
    can_read = []
    can_update = []
    can_delete = []

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


class BasePermission(Permission):

    def __init__(self, config, action):
        super(BasePermission, self).__init__()
        self.config = config
        self.permission_list = self.config.get_permission_list(action)

    @property
    def needs(self):
        # Needs caching cannot be done here, since sometimes depends on the
        # record. It must be implemented in each generator.
        needs = set()
        for needs_generator in self.permission_list:
            needs = needs.union(needs_generator.needs())
        return needs

    @property
    def excludes(self):
        # Needs caching cannot be done here, since sometimes depends on the
        # record. It must be implemented in each generator.
        excludes = set()
        for excludes_generator in self.permission_list:
            excludes = excludes.union(excludes_generator.excludes())
        return excludes

    @property
    def query_filter(self):
        query_filters = Q()
        for qf_generator in self.permission_list:
            query_filters = query_filters | qf_generator.query_filter()
        return query_filters
