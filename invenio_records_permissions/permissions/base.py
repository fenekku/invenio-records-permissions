# -*- coding: utf-8 -*-
#
# Copyright (C) 2019 CERN.
#
# Invenio-Records-Permissions is free software; you can redistribute it
# and/or modify it under the terms of the MIT License; see LICENSE file for
# more details.
from itertools import chain

from flask import current_app
from invenio_access import Permission
from ..generators import Deny


# Guillaume: We want inheritance from it, so we can ditch the leading `_`
class _PermissionConfig(object):

    # Deny all by default
    can_create = [Deny]
    can_list = [Deny]
    can_read = [Deny]
    can_update = [Deny]
    can_delete = [Deny]
    # Guillaume: 'actions' -> [] mapping
    # Why not merge this with BasePermission or perhaps investigate Meta class

    @classmethod
    def get_gate_list(cls, action):
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
    def __init__(self, action, **over):
        super(BasePermission, self).__init__()
        self.action = action
        self.over = over

    # @property
    # def needs(self):
    #     # Needs caching cannot be done here, since sometimes depends on the
    #     # record. It must be implemented in each generator.
    #     needs = []
    #     for needs_generator in self.gate_list:
    #         tmp_need = needs_generator.needs()
    #         if tmp_need:
    #             needs.extend(tmp_need)

    #     self.explicit_needs = self.explicit_needs.union(needs)
    #     self._load_permissions()

    #     return self._permissions.needs

    @property
    def needs(self):
        # NOTE: This is now generic
        # NOTE: This enforces either of the needs
        needs = [
            gate.needs(**self.over) for gate in self.gate_list
        ]
        needs = set(chain.from_iterable(needs))

        self.explicit_needs |= needs
        self._load_permissions()  # explicit_needs is used here
        return self._permissions.needs

    # @property
    # def excludes(self):
    #     excludes = []
    #     for excludes_generator in self.gate_list:
    #         tmp_exclude = excludes_generator.excludes()
    #         if tmp_exclude:
    #             excludes.extend(tmp_exclude)

    #     self.explicit_needs = self.explicit_needs.union(excludes)
    #     self._load_permissions()

    #     return self._permissions.excludes

    @property
    def excludes(self):
        # NOTE: This is now generic
        # NOTE: This enforces either of the excludes
        # Guillaume: There should be a note about what happens when excludes
        #            and needs clash
        excludes = [
            gate.excludes(**self.over) for gate in self.gate_list
        ]
        excludes = set(chain.from_iterable(excludes))
        # self.explicit_excludes |= excludes  # See Pablo issue
        self._load_permissions()
        return self._permissions.excludes

    # @property
    # def query_filter(self):
    #     query_filters = []
    #     for qf_generator in self.gate_list:
    #         tmp_query_filter = qf_generator.query_filter()
    #         if tmp_query_filter:
    #             query_filters.append(tmp_query_filter)
    #     return query_filters

    @property
    def query_filters(self):
        # NOTE: Made plural because multiple filters are returned
        # NOTE: This is now generic
        # NOTE: This acts as either
        filters = [
            gate.query_filter(**self.over) for gate in self.gate_list
        ]
        return [f for f in filters if f]
