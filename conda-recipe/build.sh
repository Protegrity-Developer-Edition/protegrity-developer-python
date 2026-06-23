#!/bin/bash

# Install the package using pip.
# --no-deps: conda already resolves runtime deps from meta.yaml requirements.run
# --no-build-isolation: use the host env's setuptools (pyproject [build-system])
$PYTHON -m pip install . -vv --no-deps --no-build-isolation
