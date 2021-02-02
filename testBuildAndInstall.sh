#!/bin/bash

# Edit key to where you stored your secret token
token=`cat secret.testpypi`

# Create the whl
python setup.py sdist bdist_wheel

# Uncomment/comment the lines below to determine the repository

# Upload to testpypi
python -m twine upload -r testpypi dist/* -u __token__ -p $token
# Upload to pypi
# python -m twine upload dist/* -u __token__ -p $token

# Install from testpypi
pip install --index-url https://test.pypi.org/simple/ cordrapy
# Install from pypi
# pip install cordrapy

python -c "import cordrapy; test=cordrapy.CordraObject(); print(test)"