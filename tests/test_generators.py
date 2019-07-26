# -*- coding: utf-8 -*-
#
# Copyright (C) 2019 CERN.
#
# Invenio-Records-Permissions is free software; you can redistribute it
# and/or modify it under the terms of the MIT License; see LICENSE file for
# more details.

""" 1
{
    "_access": {
        "metadata_restricted": false,
        "files_restricted": false
    },
    "access_right": "open",
    "title": "This record is fully open",
    "description": "This record is meta and files restricted false, and open",
    "owners": [1, 2, 3]
}
"""

""" 2
{
    "_access": {
        "metadata_restricted": false,
        "files_restricted": true
    },
    "access_right": "open",
    "title": "This record is half-open",
    "description": "This record is meta are public and the record is open but files  are restricted",
    "owners": [1, 2, 3]
}
"""

""" 3
{
    "_access": {
        "metadata_restricted": true,
        "files_restricted": true
    },
    "access_right": "restricted",
    "title": "This record is half-open",
    "description": "This record is meta are public and the record is open but files  are restricted",
    "owners": [1, 2, 3]
}
"""

"""
# This case is not contemplated. Meta and files private but open? No sense.
{
    "_access": {
        "metadata_restricted": true,
        "files_restricted": true
    },
    "access_right": "open",
    "title": "This record is half-open",
    "description": "This record is meta are public and the record is open but files  are restricted",
    "owners": [1, 2, 3]
}
"""

"""
# This case is not contemplated. Meta and files public but restricted? No sense.
{
    "_access": {
        "metadata_restricted": false,
        "files_restricted": false
    },
    "access_right": "restricted",
    "title": "This record is half-open",
    "description": "This record is meta are public and the record is open but files  are restricted",
    "owners": [1, 2, 3]
}
"""

"""
# This case is not contemplated. Meta private but open and files public?? No sense.
{
    "_access": {
        "metadata_restricted": true,
        "files_restricted": false
    },
    "access_right": "open",
    "title": "This record is fully open",
    "description": "This record is meta and files restricted false, and open",
    "owners": [1, 2, 3]
}
"""
