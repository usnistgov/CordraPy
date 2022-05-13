"""Check the CordraClient Class and its functionality. Should be able to fully reproduce the 
functionality of the Cordra REST API. This includes:
* Authorization using user / password
* Authorization using a secret key
* Provide a token for subsequent authorization
* Delete a token
* Create a cordra object
* Create a cordra object with payload
* Setting the ACL on a cordra object on create
* Updating a cordra object
* Updating a cordra object attribute
* Updating a cordra object payload
* Updating the ACL of a cordra object
* Deleting a cordra object
* Deleting a cordra object attribute
* Deleting a cordra object payload
* Querying cordra

The CordraClient also provides the additional features:
* Reading all schemas from a remote Cordra instance and turning them into python classes
"""


from cordra import CordraClient, CordraObject
from io import BytesIO
from PIL import Image
import json
import requests
import copy


# Deepcopy inputs to force a local scope
def deepcopy(func):
    def wrap(*args, **kwargs):
        args = list(args)
        for i, arg in enumerate(args):
            args[i] = copy.deepcopy(arg)
        for k, v in enumerate(kwargs):
            kwargs[k] = copy.deepcopy(v)
        return func(*args, **kwargs)
    return wrap


# Connect to the test repository
repository = CordraClient(host="https://localhost:8443/", credentials_file="secretlogin.json", verify=False)

# Define the document object without a remote repository
document = CordraObject({"_type":"Document", "awesome":"superb"})

# Define a document object with JSON and Image payloads
document_payloads = CordraObject(_type="Document")
J = {"a": "a", "b":"b"}
document_payloads.add("document.json", json.dumps(J).encode()) # Add a json payload as bytes

stream = BytesIO()
A = Image.radial_gradient("L").resize((11,11))
A.save(stream, format="PNG") # Write a png image to bytes object
document_payloads.add("radial.png", stream.getvalue()) # Add the png (in bytes) as payload




# Test 1 - Check that a python CordraObject can be created and updated locally and correctly 
# write to Cordra
@deepcopy
def Test1(document):
    document.hello = "world" # Update the python instance

    print(document)
    print(document._type)

    r = repository.create(document) # Write to Cordra
    print(json.dumps(r, indent=2))
    document.id = str( r["id"] ) # Update the id from None to the id assigned by Cordra

    document_remote = repository.read( document.id ) # Read the cordra object and compare to local

    assert document.dict() == document_remote.dict(), \
        "Remote and local objects are note the same." # Check equivalence of objects' dicts

    return document




# Test 2 - Check that local and remote payloads are equal
@deepcopy
def Test2(document):
    r = repository.create(document) # Create cordra object with payloads
    document.id = str( r["id"] ) # Update the id from None to the id assigned by Cordra

    document_remote = repository.read( document.id, getAll=True ) # Read the Object and Payloads

    K = json.loads( document_remote.get("document.json").decode('utf-8') ) # Decode payload bytes
    assert J==K, "JSON payload was corrupted."

    B = document_remote.get("radial.png")
    assert stream.getvalue()==B, "Image bytes were corrupted."

    return document




# Test 3 - Check that an update can be successfully written to an object that already exists
# in Cordra.
@deepcopy
def Test3(document):
    r = repository.create(document)
    document.id = str( r["id"] )

    # Update everything but payloads (faster updates)
    document.awesome = "wonderful" # Update the existing attributes of object
    document.updateditem = "SendUpdate" # Update new attributes of object
    repository.update(document, updatePayloads=False)

    document_remote = repository.read( document.id ) # Check that the updated objects are the same
    assert document.dict() == document_remote.dict(), \
        "Updated object attributes differ after synced update."


    # Update everything
    L = {"c": "c", "d":"d"}
    document.add("document.json", json.dumps(L).encode()) # Update the JSON payload
    repository.update(document)

    document_remote = repository.read( document.id, getAll=True )
    K = json.loads( document_remote.get("document.json").decode('utf-8') )
    assert L==K, "JSON payloads differ after synced update."

    return document




# Test 4 - Deletion of payloads and properties
@deepcopy
def Test4(document):
    # Delete a payload
    # Verify local no longer has the payload
    # Verify local and remote are the same
    # Delete a property of object
    # Verify local no longer has the property
    # Verify local and remote are the same
    return document




# Test 5 - Update ACLs
@deepcopy
def Test5():
    ## create user
    guest = CordraObject(type="User", username="guest", password="guestpassword...1", 
                         requirePasswordChange=False)
    r = repository.create(guest)
    guest.id = r["id"]

    ## create object with ACL that includes created user
    ## create an engine with the new user credentials
    ## check that object can be edited by the new user
    return document




# Test 6 - Delete an object
@deepcopy
def Test6(document):
    # Delete the object
    repository.delete(document)
    # Verify the object does not exist
    try:
        repository.read(document.id)
        assert False, "Object was NOT deleted"
    except requests.exceptions.HTTPError:
        pass





if __name__ == "__main__":
    documents_returned = [
        Test1(document),
        Test2(document_payloads),
        Test3(document_payloads),
        Test4(document_payloads),
        Test5(document)
    ]

    for i, d in enumerate( documents_returned ):
        if d.id is not None: Test6(d)
