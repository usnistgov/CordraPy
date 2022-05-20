# Standard Library packages
from typing import Dict
import json
import os
from copy import deepcopy

# Local imports
from .cordra import CordraObject, Token, check_response


class CordraClient:
    """
    Supports CRUD operations with a running Cordra instance allows access to the full 
    functionality of the Cordra REST API. This includes:
    * Authorization using user / password
    * Authorization using a secret key
    * Provide a token for subsequent authorization
    * Delete a token
    * Create a cordra object
    * Setting the ACL on a cordra object on create
    * Updating a cordra object
    * Updating a cordra object attribute
    * Updating a cordra object payload
    * Updating the ACL of a cordra object
    * Deleting a cordra object
    * Deleting a cordra object attribute
    * Deleting a cordra object payload
    * Querying cordra

    Attributes:
        host: the location of the cordra instance (URL).
        credentials_file: the location of a user's credentials.
        credentials_token: a credentials token file.
        params: parameters that will be passed with each request.

    >>> import cordra
    >>> test_object = cordra.CordraClient("testhost")
    >>> print(test_object)
    Connection via CordraPy to testhost
    """

    host: str #URL
    handle: str="prefix"
    username: str
    password: str
    secret_key_path: str #FilePath
    params: Dict


    def __str__(self): 
        return f"Connection via CordraPy to {self.host}"


    def __init__(self, **params):
        assert "host" in params, "Host must be specified to use CordraClient"
        assert ("username" in params and "password" in params) or "secret_key_path" in params, \
            "Client requires `username` and `password` params or a `secret_key_path` param"
        self.params = dict()
        self.params.update(params)
        
        if "username" in params:
            self.get_auth()
            del self.params["username"]
            del self.params["password"]
        elif "secret_key_path" in params:
            raise NotImplementedError
        else:
            raise Exception

        self.schemas = {
            r.get("name"): r.get("schema")
            for r in self.find("type:Schema")['results']
        }


    def get_auth(self):
        """Get a token with credentials"""
        r = Token.create(**self.params)

        # Set up variables and default auth for future requests
        self.params["token"] = r["access_token"]


    def check_auth(self):
        """Checks an access Token"""
        r = Token.read(**self.params)
        return r


    def delete_auth(self):
        """Delete an access Token"""
        r = Token.delete(**self.params)
        return r


    def create(self, obj, obj_type, **kwargs):
        """Creates an object"""

        params = deepcopy(self.params)
        params.update(kwargs)

        return CordraObject.create(obj_json=obj, obj_type=obj_type, **params)


    def read(self, obj_id, getObjPayTuple=False, **kwargs):
        """Retrieve an object from Cordra by identifer and create a
        python CordraObject."""

        params = deepcopy(self.params)
        params.update(kwargs)

        if getObjPayTuple:
            params["full"] = True

        obj = CordraObject.read(obj_id=obj_id, **params)

        if getObjPayTuple:
            if "payloads" not in obj:
                return (obj["content"], None)
                
            payload_info = deepcopy( obj["payloads"] )
            obj["payloads"] = dict()
            payload_info = CordraObject.read_payload_info(obj_id=obj_id, **params)

            for pay in payload_info:
                payName = pay.get("name")
                obj["payloads"][payName] = CordraObject.read_payload(obj_id=obj_id, payload=payName, **params)

            return (obj["content"], obj["payloads"])

        return obj


    def update(self, obj, obj_id, **kwargs):
        """Updates an object"""

        params = deepcopy(self.params)
        params.update(kwargs)

        return CordraObject.update(obj_id=obj_id, obj_json=obj, **params)


    def delete(self, obj_id, **kwargs):
        """Delete a Cordra object or part of a Cordra Object"""

        params = deepcopy(self.params)
        params.update(kwargs)

        return CordraObject.delete(obj_id=obj_id, **params)


    def find(self, query, **kwargs):
        """Find a Cordra object by query"""

        params = deepcopy(self.params)
        params.update(kwargs)

        return CordraObject.find(query=query, **params)
