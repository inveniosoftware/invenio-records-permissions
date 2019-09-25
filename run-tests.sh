#!/usr/bin/env sh
# -*- coding: utf-8 -*-
#
# Copyright (C) 2019 CERN.
#
# Invenio-Records-Permissions is free software; you can redistribute it
# and/or modify it under the terms of the MIT License; see LICENSE file for
# more details.

pydocstyle invenio_records_permissions tests docs && \
isort --recursive --check-only --diff && \
check-manifest --ignore ".travis-*,.vscode*" && \
sphinx-build -qnNW docs docs/_build/html && \
python setup.py test
