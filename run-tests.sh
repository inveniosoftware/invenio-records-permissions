#!/usr/bin/env sh
# -*- coding: utf-8 -*-
#
# Copyright (C) 2019 CERN.
# Copyright (C) 2019 Northwestern University.
#
# Invenio-Records-Permissions is free software; you can redistribute it
# and/or modify it under the terms of the MIT License; see LICENSE file for
# more details.

pydocstyle invenio_records_permissions tests docs && \
isort invenio_records_permissions tests --check-only --diff && \
check-manifest --ignore ".travis-*,.vscode*" && \
sphinx-build -qnNW docs docs/_build/html && \
docker-services-cli up es postgresql
python -m pytest
tests_exit_code=$?
docker-services-cli down
exit "$tests_exit_code"
