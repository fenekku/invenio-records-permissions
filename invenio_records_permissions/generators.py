# -*- coding: utf-8 -*-
#
# Copyright (C) 2019 CERN.
# Copyright (C) 2019 Northwestern University.
#
# Invenio-Records-Permissions is free software; you can redistribute it
# and/or modify it under the terms of the MIT License; see LICENSE file for
# more details.

"""Invenio Records Permissions Generators."""

import json

from elasticsearch_dsl.query import Q
from flask import g
from flask_principal import ActionNeed, UserNeed
from invenio_access.permissions import any_user
from invenio_files_rest.models import Bucket, ObjectVersion
from invenio_records_files.api import Record
from invenio_records_files.models import RecordsBuckets


class Generator(object):
    """Parent class mapping the context when an action is allowed or denied.

    It does so by *generating* "needed" and "excluded" Needs. At the search
    level it implements the *query filters* to restrict the search.

    Any context inherits from this class.
    """

    def needs(self, **kwargs):
        """Enabling Needs."""
        return []

    def excludes(self, **kwargs):
        """Preventing Needs."""
        return []

    def query_filter(self, **kwargs):
        """Elasticsearch filters."""
        return []


class AnyUser(Generator):
    """Allows any user."""

    def __init__(self):
        """Constructor."""
        super(AnyUser, self).__init__()

    def needs(self, **kwargs):
        """Enabling Needs."""
        return [any_user]

    def query_filter(self, **kwargs):
        """Match all in search."""
        return Q('match_all')


class Deny(Generator):
    """Denies ALL users (except super users)."""

    def __init__(self):
        """Constructor."""
        super(Deny, self).__init__()

    def excludes(self, **kwargs):
        """Preventing Needs."""
        return [any_user]

    def query_filter(self, **kwargs):
        """Match None in search."""
        return ~Q('match_all')


class Admin(Generator):
    """Allows users with admin-access (different from superuser-access)."""

    def __init__(self):
        """Constructor."""
        super(Admin, self).__init__()

    def needs(self, **kwargs):
        """Enabling Needs."""
        return [ActionNeed('admin-access')]


class RecordOwners(Generator):
    """Allows record owners."""

    def needs(self, record=None, **kwargs):
        """Enabling Needs."""
        return [UserNeed(owner) for owner in record.get('owners', [])]

    def query_filter(self, record=None, **kwargs):
        """Filters for current identity as owner."""
        provides = g.identity.provides
        for need in provides:
            if need.method == 'id':
                return Q('term', owners=need.value)
        return []


class AnyUserIfPublic(Generator):
    """Allows any user if record is open access.

    TODO: Revisit when dealing with files.
    """

    def needs(self, record=None, **rest_over):
        """Enabling Needs."""
        is_open = (
            record and record.get('access_right') == "open"
        )
        return [any_user] if is_open else []

    def query_filter(self, *args, **kwargs):
        """Filters for non-restricted records."""
        return Q('term', **{"access_right": "open"})


class AllowedIdentities(Generator):
    """Allows additional explicit users/roles/groups...

    Name "identity" is used bc it correlates with flask-principal identity
    while not being one.
    """

    def __init__(self, action='read'):
        """Constructor."""
        self.action = action
        self.can = 'can_' + str(self.action)

    def needs(self, record=None, **kwargs):
        """Enabling UserNeeds for each person.

        TODO: Organization and role needs
        """
        if not record:
            return []

        return [
            UserNeed(identity.get('id')) for identity in
            record.get('sys', {}).get('permissions', {}).get(self.can, [])
            if identity.get('type') == 'person' and identity.get('id')
        ]

    def query_filter(self, *args, **kwargs):
        """Filters for non-restricted records."""
        for need in g.identity.provides:
            if need.method == 'id':
                return Q('term', **{
                    "sys.permissions." + self.can: {
                        "type": "person", "id": need.value
                    }
                })


class GlobalCurators(Generator):
    """Allows Global Curators."""

    # TODO: Implement me after deposits have been discussed
    pass


class LocalCurators(Generator):
    """Allows Local Curators."""

    # TODO: Implement me after deposits have been discussed
    pass


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
