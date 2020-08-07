import requests
import json

from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# global variables
objects_endpoint = 'objects/'
acls_endpoint = 'acls/'
token_create_endpoint = 'auth/token'
token_read_endpoint = 'auth/introspect'
token_delete_endpoint = 'auth/revoke'
token_grant_type = 'password'
token_type = 'Bearer'

def endpoint_url(host, endpoint):
    return host.strip('/') + '/' + endpoint


def check_response(response):
    if not response.ok:
        try:
            print(response.json())
        except BaseException:
            print(response.text)
        response.raise_for_status()
        return None
    else:
        try:
            return response.json()
        except BaseException:
            return response.text


def set_auth(username, password):
    if username and password:
        auth = requests.auth.HTTPBasicAuth(username, password)
    else:
        auth = None
    return auth

def get_token_value(token):
    if isinstance(token, str):
        return token
    elif isinstance(token, dict):
        try:
            return token['access_token']
        except:
            raise Exception('Token json format error.')
    else:
        raise Exception('Token format error.')


def set_headers(token):
    if token:
        headers = dict()
        headers['Authorization'] = token_type + ' ' + get_token_value(token)
    else:
        headers = None
    return headers

class Objects:
    def create(
        host,
        obj_json,
        obj_type,
        handle=None,
        suffix=None,
        dryRun=False,
        username=None,
        password=None,
        token=None,
        verify=None,
        full=False,
        payloads=None,
        acls=None
    ):
        '''Create a Cordra object'''

        params = dict()
        params['type'] = obj_type
        if handle:
            params['handle'] = handle
        if suffix:
            params['suffix'] = suffix
        if dryRun:
            params['dryRun'] = dryRun
        if full:
            params['full'] = full

        if payloads:  # multi-part request
            data = dict()
            data['content'] = json.dumps(obj_json)
            if acls:
                data['acl'] = json.dumps(acls)
            r = check_response(
                requests.post(
                    endpoint_url(host, objects_endpoint),
                    params=params,
                    files=payloads,
                    data=data,
                    auth=set_auth(
                        username,
                        password),
                    headers=set_headers(token),
                    verify=verify))
            return r
        else:  # simple request
            if acls:
                params['full'] = True
            obj_r = check_response(
                requests.post(
                    endpoint_url(host, objects_endpoint),
                    params=params,
                    data=json.dumps(obj_json),
                    auth=set_auth(
                        username,
                        password),
                    headers=set_headers(token),
                    verify=verify))

            if acls and not dryRun:
                obj_id = obj_r['id']
                acl_r = check_response(
                    requests.put(
                        endpoint_url(host, acls_endpoint) + obj_id,
                        params=params,
                        data=json.dumps(acls),
                        auth=set_auth(
                            username,
                            password),
                        headers=set_headers(token),
                        verify=verify))
                return [obj_r,acl_r]
            else:
                return obj_r

    def read(
        host,
        obj_id,
        username=None,
        password=None,
        token=None,
        verify=None,
        jsonPointer=None,
        jsonFilter=None,
        full=False
    ):
        '''Retrieve a Cordra object JSON by identifer.'''

        params = dict()
        params['full'] = full
        if jsonPointer:
            params['jsonPointer'] = jsonPointer
        if jsonFilter:
            params['filter'] = str(jsonFilter)
        r = check_response(
            requests.get(
                endpoint_url(host, objects_endpoint) + obj_id,
                params=params,
                auth=set_auth(
                    username,
                    password),
                headers=set_headers(token),
                verify=verify))
        return r

    def read_payload_info(
        host,
        obj_id,
        username=None,
        password=None,
        token=None,
        verify=None
    ):
        '''Retrieve a Cordra object payload names by identifer.'''

        params = dict()
        params['full'] = True
        r = check_response(
            requests.get(
                endpoint_url(host, objects_endpoint) + obj_id,
                params=params,
                auth=set_auth(
                    username,
                    password),
                headers=set_headers(token),
                verify=verify))
        return r['payloads']

    def read_payload(
        host,
        obj_id,
        payload,
        username=None,
        password=None,
        token=None,
        verify=None
    ):
        '''Retrieve a Cordra object payload by identifer and payload name.'''

        params = dict()
        params['payload'] = payload
        r = check_response(
            requests.get(
                endpoint_url(host, objects_endpoint) + obj_id,
                params=params,
                auth=set_auth(
                    username,
                    password),
                headers=set_headers(token),
                verify=verify))
        return r

    def update(
        host,
        obj_id,
        obj_json=None,
        jsonPointer=None,
        obj_type=None,
        dryRun=False,
        username=None,
        password=None,
        token=None,
        verify=None,
        full=False,
        payloads=None,
        payloadToDelete=None,
        acls=None
    ):
        '''Update a Cordra object'''
    
        params = dict()
        if obj_type:
            params['type'] = obj_type
        if dryRun:
            params['dryRun'] = dryRun
        if full:
            params['full'] = full
        if jsonPointer:
            params['jsonPointer'] = jsonPointer
        if payloadToDelete:
            params['payloadToDelete'] = payloadToDelete
        
        if payloads:  # multi-part request
            if not obj_json:
                raise Exception('obj_json is required when updating payload')
            data = dict()
            data['content'] = json.dumps(obj_json)
            data['acl'] = json.dumps(acls)
            r = check_response(
                requests.put(
                    endpoint_url(host, objects_endpoint) + obj_id,
                    params=params,
                    files=payloads,
                    data=data,
                    auth=set_auth(
                        username,
                        password),
                    headers=set_headers(token),
                    verify=verify))
            return r
        elif acls: # just update ACLs
            r = check_response(
                requests.put(
                    endpoint_url(host, acls_endpoint) + obj_id,
                    params=params,
                    data=json.dumps(acls),
                    auth=set_auth(
                        username,
                        password),
                    headers=set_headers(token),
                    verify=verify))
            return r
        else:  # just update object
            if not obj_json:
                raise Exception('obj_json is required')
            r = check_response(
                requests.put(
                    endpoint_url(host, objects_endpoint) + obj_id,
                    params=params,
                    data=json.dumps(obj_json),
                    auth=set_auth(
                        username,
                        password),
                    headers=set_headers(token),
                    verify=verify)
                )
            return r


    def delete(
        host,
        obj_id,
        jsonPointer=None,
        username=None,
        password=None,
        token=None,
        verify=None
    ):
        '''Delete a Cordra object'''

        params = dict()
        if jsonPointer:
            params['jsonPointer'] = jsonPointer

        r = check_response(
            requests.delete(
                endpoint_url(host, objects_endpoint) + obj_id,
                params=params,
                auth=set_auth(
                    username,
                    password),
                headers=set_headers(token),
                verify=verify)
            )
        return r

    def find(
        host,
        query,
        username=None,
        password=None,
        token=None,
        verify=None,
        ids=False,
        jsonFilter=None,
        full=False
    ):
        '''Find a Cordra object by query'''

        params = dict()
        params['query'] = query
        params['full'] = full
        if jsonFilter:
            params['filter'] = str(jsonFilter)
        if ids:
            params['ids'] = True 
        r = check_response(
            requests.get(
                endpoint_url(host, objects_endpoint),
                params=params,
                auth=set_auth(
                    username,
                    password),
                headers=set_headers(token),
                verify=verify))
        return r

class Token:
    def create(
        host,
        username,
        password,
        verify=None,
        full=False
    ):
        '''Create an access Token'''
        
        params = dict()
        params['full'] = full

        auth_json = dict()
        auth_json['grant_type'] = token_grant_type
        auth_json['username'] = username
        auth_json['password'] = password

        r = check_response(
            requests.post(
                endpoint_url(host, token_create_endpoint),
                params=params,
                data=auth_json,
                verify=verify))
        return r

    def read(
        host,
        token,
        verify=None,
        full=False
    ):
        '''Read an access Token'''

        params = dict()
        params['full'] = full

        auth_json = dict() 
        auth_json['token'] = get_token_value(token)

        r = check_response(
            requests.post(
                endpoint_url(host, token_read_endpoint),
                params=params,
                data=auth_json,
                verify=verify
            ))
        return r

    def delete(
        host,
        token,
        verify=None
    ):
        '''Delete an access Token'''

        auth_json = dict() 
        auth_json['token'] = get_token_value(token)

        r = check_response(
            requests.post(
                endpoint_url(host, token_delete_endpoint),
                data=auth_json,
                verify=verify
            ))
        return r