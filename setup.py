""" This is a simple Python library for interacting with the REST interface of an instance of Cordra.
"""

from setuptools import setup, find_packages

def fetch_requirements():
    required = []
    with open('requirements.txt') as f:
        required = f.read().splitlines()
    return required


PACKAGE_NAME = "CordraPy"

setup(
    name=PACKAGE_NAME,
    version='0.3.2',
    description='Python client interface to a cordra instance',
    author='Zachary Trautt, Faical Yannick Congo, Sven Voigt',
    author_email='zachary.trautt@nist.gov',
    include_package_data=True,
    install_requires=fetch_requirements(),
    packages=find_packages()
)
