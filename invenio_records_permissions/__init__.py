# -*- coding: utf-8 -*-
#
# Copyright (C) 2019-2024 CERN.
# Copyright (C) 2019-2024 Northwestern University.
# Copyright (C) 2024 Graz University of Technology.
#
# Invenio-Records-Permissions is free software; you can redistribute it
# and/or modify it under the terms of the MIT License; see LICENSE file for
# more details.

r"""Permission generators and policies for Invenio records.

Invenio-records-permissions provides a means to fully customize access control
for Invenio records. It does so by defining and providing three layers of
permission constructs that build on each other:
Generators and Policies. You can extend or override them for maximum
control. Thankfully we provide default ones that cover most cases.

Invenio-records-permissions conveniently structures (and relies on)
functionalities from
`invenio-access <https://invenio-access.readthedocs.io>`_ and
`flask-principal <https://pythonhosted.org/Flask-Principal>`_ .


Generators
----------

Generators are the lowest level of abstraction provided by
invenio-records-permissions. A
:py:class:`~invenio_records_permissions.generators.Generator` represents
identities via
`Needs <https://invenio-access.readthedocs.io/en/latest/api.html#needs>`_ that
are allowed or disallowed to act on a kind of object. A Generator does not
specify the action, but it does specify who is allowed and the kind of object
of concern (typically records). Generators *generate* required and forbidden
Needs at the object-of-concern level and *generate* query filters
at the search-for-objects-of-concern level.

A Generator object defines 3 methods in addition to its constructor:

- ``needs(self, **kwargs)``: returns Needs, one of which a provider is
                             required to have to be allowed
- ``excludes(self, **kwargs)``: returns a list of Needs disallowing any
                                provider of a single one
- ``query_filter(self, **kwargs)``: returns a query filter to enable retrieval
                                    of records

The ``needs`` and ``excludes`` methods specify access conditions from
the point-of-view of the object-of-concern; whereas, the ``query_filter``
method specifies those from the actor's point-of-view in search scenarios.

A simple example of a Generator is the provided
:py:class:`~invenio_records_permissions.generators.RecordOwners` Generator:

.. code-block:: python

    from flask_principal import UserNeed


    class RecordOwners(Generator):
        '''Allows record owners.'''

        def needs(self, record=None, **kwargs):
            '''Enabling Needs.'''
            return [UserNeed(owner) for owner in record.get('owners', [])]

        def query_filter(self, record=None, **kwargs):
            '''Filters for current identity as owner.'''
            # NOTE: implementation subject to change until permissions metadata
            #       settled
            provides = g.identity.provides
            for need in provides:
                if need.method == 'id':
                    return Q('term', owners=need.value)
            return []

``RecordOwners`` allows any identity providing a `UserNeed
<https://pythonhosted.org/Flask-Principal/#flask_principal.UserNeed>`_
of value found in the ``owners`` metadata of a record. The
``query_filter(self, **kwargs)``
method outputs a query that returns all owned records of the current user.
Not included in the above, because it doesn't apply to ``RecordOwners``, is
the ``excludes(self, **kwargs)`` method.

.. Note::

    Exclusion has priority over inclusion. If a Need is returned by both
    ``needs`` and ``excludes``, providers of that Need will be **excluded**.

If implementation of Generators seems daunting, fear not! A collection of
them has already been implemented in
:py:mod:`~invenio_records_permissions.generators`
and they cover most cases you may have.

To fully understand how they work, we have to show where Generators are used.
That is in the Policies.


Policies
--------

Classes inheriting from
:py:class:`~invenio_records_permissions.policies.base.BasePermissionPolicy` are
referred to as Policies. They list **what actions** can be done **by whom**
over an implied category of objects (typically records). A Policy is
instantiated on a per action basis and is a descendant of `Permission
<https://invenio-access.readthedocs.io/en/latest/api.html
#invenio_access.permissions.Permission>`_ in
`invenio-access <https://invenio-access.readthedocs.io>`_ .
Generators are used to provide the "by whom" part and the implied category of
object.

Here is an example of a custom record Policy:

.. code-block:: python

    from invenio_records_permissions.generators import AnyUser, RecordOwners
    from invenio_records_permissions.policies.base import BasePermissionPolicy

    class ExampleRecordPermissionPolicy(BasePermissionPolicy):
        can_create = [AnyUser()]
        can_search = [AnyUser()]
        can_read = [AnyUser()]
        can_update = [RecordOwners()]

The actions are class variables of the form: ``can_<action>`` and the
corresponding (dis-)allowed identities are a list of Generator instances.
One can define any action as long as it follows that pattern and
is verified at the moment it is undertaken.

In the example above, any user can create, list and read records, but only
a record's owner can edit it and only super users can perform the "foo_bar"
action.

We recommend you extend the provided
:py:class:`invenio_records_permissions.policies.records.RecordPermissionPolicy`
to customize record permissions for your instance.
This way you benefit from sane defaults.

After you have defined your own Policy, set it in your configuration:

.. code-block:: python

    RECORDS_PERMISSIONS_RECORD_POLICY = (
        'module.to.ExampleRecordPermissionPolicy'
    )

The succinct encoding of the permissions for your instance gives you
    - one central location where your permissions are defined
    - exact control
    - great flexibility by defining your own actions, generators and policies
"""

from .ext import InvenioRecordsPermissions
from .policies import BasePermissionPolicy, RecordPermissionPolicy

__version__ = "1.0.0"

__all__ = (
    "__version__",
    "BasePermissionPolicy",
    "InvenioRecordsPermissions",
    "RecordPermissionPolicy",
)
