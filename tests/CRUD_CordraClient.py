"""Check the CordraClient Class and its functionality. Should be able to fully reproduce the 
functionality of the Cordra REST API. This includes the following tests:
* Authorize using user / password
* Authorize using a secret key
* Maintain a token for subsequent authorization
* Delete an authorization token
* Create a cordra object and read back an identical object
* Create a cordra object with a json payload and read back an identical json object
* Create a cordra object with a csv payload and read back an identical csv object
* Create a cordra object with an image payload and read back an identical image
* Update a cordra object and read back an object with the changes
* Update a json payload and read back an identical json object
* Update a csv payload and read back an identical csv object
* Update an image payload and read back an identical image
* Set the ACL on a cordra object on create and verify only specified readers have access
* Update the ACL of a cordra object and verify only current specified readers have access
* Delete a cordra object with a user and verify it doesn't exist with admin
* Delete a cordra object attribute and read the object to verify deletion
* Delete a cordra object payload and read the object to verify deletion
* Query cordra for all created objects and delete them
"""

# from cordra import CordraObject
from cordra import CordraClient, CordraObject
from io import BytesIO
from PIL import Image
import os
import json
import requests
import copy


# ---------------- #
# Helper Functions #
# ---------------- #
def auth_wrapper(func):
    '''Reusability of the auth code'''
    def inner():
        client = CordraClient(
            host="https://localhost:8443/", 
            username="admin", password="admin", 
            verify=False
        )
        func(client)
        client.delete_auth()

    return inner


def acl_wrapper(func):
    '''Generating clients for admin and two users.'''
    def inner():
        client = CordraClient(
            host="https://localhost:8443/", 
            username="admin", password="admin", 
            verify=False
        )

        client_user1 = CordraClient(
            host="https://localhost:8443/", 
            username="user1", password="user.1234", 
            verify=False
        )

        client_user2 = CordraClient(
            host="https://localhost:8443/", 
            username="user2", password="user.1234", 
            verify=False
        )

        user1_id = client.find('/username:"user1"')["results"][0]["id"]
        user2_id = client.find('/username:"user2"')["results"][0]["id"]

        func(client, user1_id, client_user1, user2_id, client_user2)
        client.delete_auth()
        client_user1.delete_auth()
        client_user2.delete_auth()

    return inner


# ----- #
# Setup #
# ----- #

@auth_wrapper
def setup(client_admin):
    '''Creating users with the admin account'''

    client_admin.create({"username": "user1", "password": "user.1234"}, "User")
    client_admin.create({"username": "user2", "password": "user.1234"}, "User")


@auth_wrapper
def teardown(client_admin):
    '''Deleting all objects and users with the admin account. Excludes schemas.
    Query cordra for all created objects and delete them.'''

    r = client_admin.find("*", pageSize=-1, full=True)
    all_objectIds = [ri['id'] for ri in r['results'] if ri['type']!='Schema']

    for obj_id in all_objectIds:
        client_admin.delete(obj_id)


# ----- #
# Tests #
# ----- #
tests = []

@auth_wrapper
def test(client):
    '''Authorize using user / password. 
    Maintain a token for subsequent authorization.
    Delete an authorization token.'''

    client.check_auth()

tests.append(test)


def test():
    '''Authorize using a secret key'''
    #TODO: implement secret key in cordraClient then write this test
    pass

tests.append(test)


@auth_wrapper 
def test(client):
    '''Create a cordra object and read back an identical object.
    Update a cordra object and read back an object with the changes.'''

    # Create object
    obj1 = {"@type": "Document", "name": "test1"}
    r = client.create(obj1, "Document")
    obj1_id = r["id"]
    obj1["id"] = obj1_id
    assert obj1 == r

    obj1_clone = client.read(obj1_id)
    assert obj1 == obj1_clone

    # Update object
    obj1.update({"name": "test1-update"})
    r = client.update(obj1, obj1_id)
    assert obj1 == r

    obj1_clone = client.read(obj1_id)
    assert obj1 == obj1_clone

tests.append(test)



@auth_wrapper
def test(client):
    '''Create a cordra object with a json payload and read back an identical json object.
    Update a json payload and read back an identical json object.'''

    obj1 = {"@type": "Document", "name": "test1"}
    pay1 = {"some_info": 123}

    # Create the obj and pay by encoding payload into bytes object
    r = client.create(obj1, "Document", payloads={"json": json.dumps(pay1)})
    obj1_id = r["id"]
    obj1["id"] = obj1_id
    assert obj1 == r

    obj1_clone, pay1_clone = client.read(obj1_id, getObjPayTuple=True)
    assert obj1 == obj1_clone
    assert pay1 == pay1_clone["json"]

    # Update the payload
    pay1 = {"other_info": 456}
    r = client.update(obj1, obj1_id, payloads={"json": json.dumps(pay1)})

    obj1_clone, pay1_clone = client.read(obj1_id, getObjPayTuple=True)
    assert obj1 == obj1_clone
    assert pay1 == pay1_clone["json"]

tests.append(test)


@auth_wrapper
def test(client):
    '''Create a cordra object with a csv payload and read back an identical csv object.
    Update a csv payload and read back an identical csv object.'''

    # Create csv
    csv = ""
    for i in range(10):
        csv += f"{2*i},{2*i+1}\n"

    csv = csv.encode()

    # Write csv to cordra
    obj1 = {"@type": "Document", "name": "test1"}
    r = client.create(obj1, "Document", payloads={"csv": csv})
    obj1_id = r["id"]
    obj1["id"] = obj1_id
    assert obj1 == r

    obj1_clone, pay1_clone = client.read(obj1_id, getObjPayTuple=True)
    assert obj1 == obj1_clone
    assert csv == pay1_clone["csv"]

    # Update csv in cordra
    csv = "\n".join(csv.decode("utf-8").split("\n")[:5]).encode()
    client.update(obj1, obj1_id, payloads={"csv": csv})

    obj1_clone, pay1_clone = client.read(obj1_id, getObjPayTuple=True)
    assert obj1 == obj1_clone
    assert csv == pay1_clone["csv"]

tests.append(test)


@auth_wrapper
def test(client):
    '''Create a cordra object with an image payload and read back an identical image.
    Update an image payload and read back an identical image.'''

    # Create image
    stream = BytesIO()
    A = Image.radial_gradient("L").resize((11,11))
    A.save(stream, format="PNG") # Write a png image to bytes object
    image = stream.getvalue()

    # Write image to cordra
    obj1 = {"@type": "Document", "name": "test1"}
    r = client.create(obj1, "Document", payloads={"image": image})
    obj1_id = r["id"]
    obj1["id"] = obj1_id
    assert obj1 == r

    obj1_clone, pay1_clone = client.read(obj1_id, getObjPayTuple=True)
    assert obj1 == obj1_clone
    assert image == pay1_clone["image"]

    # Update image
    stream = BytesIO()
    A = A.resize((9,9))
    A.save(stream, format="PNG") # Write a png image to bytes object
    image = stream.getvalue()

    r = client.update(obj1, obj1_id, payloads={"image": image})

    obj1_clone, pay1_clone = client.read(obj1_id, getObjPayTuple=True)
    assert obj1 == obj1_clone
    assert image == pay1_clone["image"]

tests.append(test)


@acl_wrapper
def test(client, user1_id, client_user1, user2_id, client_user2):
    '''Set the ACL on a cordra object on create and verify only specified readers have access.
    Update the ACL of a cordra object and verify only current specified readers have access.'''

    # Create object and only allow user1 access
    r = client.create(
        {"name": "unaccessible"}, 
        "Document", 
        acls={"readers":[user1_id],"writers":None}
    )
    obj_id = r[0]['id']

    client_user1.read(obj_id)

    # this should return a 403 error
    try:
        client_user2.read(obj_id)
    except Exception as e:
        print("Successful error: ", e)

    # Update access to user2
    r = client.update(dict(), obj_id, acls={"readers":[user2_id],"writers":None})

    client_user2.read(obj_id)

    # this should return a 403 error
    try:
        client_user1.read(obj_id)
    except Exception as e: 
        print("Successful error: ", e)

tests.append(test)


@acl_wrapper
def test(client, user1_id, client_user1, user2_id, client_user2):
    '''Delete a cordra object with a user and verify it doesn't exist with admin'''
    r = client_user1.create({"deleteThis": True}, "Document")
    obj_id = r["id"]
    client_user1.delete(obj_id)

    # should return a 404 not found error
    try:
        client.read(obj_id)
    except Exception as e:
        print("Successful error: ", e)

tests.append(test)


# @acl_wrapper
# def test(client, user1_id, client_user1, user2_id, client_user2):
#     '''Delete a cordra object attribute and read the object to verify deletion'''
#     r = client_user1.create({"keepThis": True, "deleteThis": True}, "Document")
#     obj_id = r["id"]

#     print(client_user1.params["token"])
#     r = CordraObject.update(host="https://localhost:8443/", obj_id=obj_id, obj_json=None, jsonPointer="/deleteThis", token=client_user1.params["token"], verify=False)

#     print(r)


#     # r = CordraObject.delete(host="https://localhost:8443/", obj_id=obj_id, jsonPointer="deleteThis", token=client_user1.params["token"], verify=False)

#     # print(r)

#     obj = client.read(obj_id)
#     print(obj)

#     assert "keepThis" in obj
#     assert "deleteThis" not in obj

# tests.append(test)


# @acl_wrapper
# def test(client, user1_id, client_user1, user2_id, client_user2):
#     '''Delete a cordra object payload and read the object to verify deletion'''

# tests.append(test)



if __name__ == "__main__":
    try:
        setup()
        for test in tests:
            test()
    finally:
        teardown()
