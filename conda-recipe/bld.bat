REM Install the package using pip.
REM --no-deps: conda already resolves runtime deps from meta.yaml requirements.run
REM --no-build-isolation: use the host env's setuptools (pyproject [build-system])
%PYTHON% -m pip install . -vv --no-deps --no-build-isolation
if errorlevel 1 exit 1
