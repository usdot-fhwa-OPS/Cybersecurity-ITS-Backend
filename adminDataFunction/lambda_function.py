import json
import boto3
import time
from botocore.exceptions import ClientError
from boto3.dynamodb.types import TypeDeserializer
from boto3.dynamodb.types import TypeSerializer

response = {
    'statusCode': 200,
    'body': ""
}

_userPoolId = 'us-east-1_R4L2tpqhr'
_clientId = '1cba1vn8dmhfl4qk65hk1pusga'
_dataTableName = 'ocsDevTable'
_permissionTableName = 'ocsUserPermissions'
_regionName = "us-east-1"

_retryDelay = 2

tempAuth = []

deserializer = TypeDeserializer()
serializer = TypeSerializer()

def handleError(e):
    print("Client Response: ")

    if e.response['Error']['Code'] == 'NotAuthorizedException':
        statusCode = 401
        body = e.response['Error']
    else:
        print("Unexpected error: %s" % e)
        
        statusCode = 400
        body = e.response['Error']

    return statusCode,body


def handleReturn(statusCode, body):

    return {
        'statusCode': statusCode,
        'headers': {
            'Access-Control-Allow-Headers': 'Content-Type',
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET,POST,PATCH,DELETE,OPTIONS'
        },
        'body': json.dumps(body, default=str)
    }


def checkUserAuthLevel(event):
    print("\ncheckUserAuthLevel: ")
    type_query = event["resource"]

    if "authorizer" in event["requestContext"]:
        groups = event["requestContext"]["authorizer"]["claims"]["cognito:groups"]

        try:
            client = boto3.client('verifiedpermissions')

            if (isinstance(groups, str)):
                groups = groups.split(',')

            for group in groups:
                body = client.is_authorized(
                    policyStoreId='JNNEApsQDyKXYRLYpB2yZK',
                    principal={
                        'entityType': 'ocs_DevPool::Group',
                        'entityId': group
                    },
                    action={
                        'actionType': 'dataFunctions::Action',
                        'actionId': type_query
                    }
                )
                
                if (body):
                    if(body["decision"] == "ALLOW"):
                        return
                    else:
                        statusCode = 401
                        body = {"Message": body["decision"]}
        except ClientError as e:
            
            statusCode,body = handleError(e)
    
    return handleReturn(statusCode, body)


def putList(client, tableName, command, dataListRaw):

    dataList = {}
    for device in dataListRaw:
        dataList.update({k: serializer.serialize(v) for k,v in device.items()})

    body = ""
    statusCode = 200
    try:

        itr = 0
        while dataList:
            if itr > 5:
                break
            time.sleep(_retryDelay ** itr - 1)
            body = client.batch_write_item(
                RequestItems={
                    tableName: [
                        {
                            command: {
                                'Item': dataList
                            }
                        },
                    ]
                },
            )

            dataList = body["UnprocessedItems"]
            itr = itr + 1
    except ClientError as e:
        
        statusCode,body = handleError(e)
    
    return handleReturn(statusCode, body)


def deleteList(client, tableName, command, dataListRaw):

    dataList = {}
    for device in dataListRaw:
        dataList.update({k: serializer.serialize(v) for k,v in device.items()})

    body = ""
    statusCode = 200
    try:

        delay = 2
        itr = 0
        while dataList:
            if itr > 5:
                break
            time.sleep(delay ** itr)
            body = client.batch_write_item(
                RequestItems={
                    tableName: [
                        {
                            "DeleteRequest": {
                                'Key': dataList
                            }
                        },
                    ]
                },
            )

            dataList = body["UnprocessedItems"]
            itr = itr + 1
    except ClientError as e:
        
        statusCode,body = handleError(e)
    
    return handleReturn(statusCode, body)


def getUserPermissions(client, username):
    
    body = ""
    statusCode = 200
    try:

        body = client.query(
                TableName=_permissionTableName,
                KeyConditionExpression= 'username = :username',
                ExpressionAttributeValues={
                    ":username": {"S": username}
                }
            )
        print("body: ")
        print(body)
        if body["Count"] != 0:
            print("Items in Body: ")
            rxItems = body["Items"]
            
            body["Items"][0] = {k: deserializer.deserialize(v) for k,v in rxItems[0].items()}
        else:
            print("Items Empty")
            body["Items"] = [[]]
            print("Created Empty List")
            print(body["Items"])
        
    except ClientError as e:
        print("Error: ")
        print(e)
        
        statusCode,body = handleError(e)
    
    return handleReturn(statusCode, body)


def getAllUserPermissions(client):
    
    body = ""
    statusCode = 200
    try:

        returnList = []
        startKey = {}
        paginate = True
        while paginate:

            if startKey:
                body = client.scan(
                    ExclusiveStartKey=startKey,
                    TableName=_permissionTableName
                )
            else:
                body = client.scan(
                    TableName=_permissionTableName
                )

            
            rxItems = body["Items"]
            txItems = []
            
            for item in rxItems:
                txItems.append({k: deserializer.deserialize(v) for k,v in item.items()})

            returnList = body["Items"] + returnList

            if "ExclusiveStartKey" in body:
                startKey = body["ExclusiveStartKey"]
            else:
                paginate = False

        body["Items"] = returnList

    except ClientError as e:
        
        statusCode,body = handleError(e)
    
    return handleReturn(statusCode, body)


def lambda_handler(event, context):
    # TODO implement

    #first = time.perf_counter()
    
    print("User Call: ")
    print(event)

    try:
        print("Checking against known Endpoints.")
        type_query = event["resource"]
        
        #print("Time Elapsed: Before Json:  " + str(time.perf_counter() - first))
        
        if isinstance(event["body"], dict):
            print("Check if Body is dict. True")
            eventBody = event["body"]
        elif event["body"] == None:
            print("Body is Empty.")
            eventBody= {}
        else:
            print("Check if Body is dict. False")
            eventBody = json.loads(event["body"])

        # Check if User is authorized to execute request endpoint.
        authLevelResponse = checkUserAuthLevel(event)

        if authLevelResponse:
            return authLevelResponse

        client =  boto3.client('dynamodb')

        print("Client Ready:")

        if str(type_query) == '/data/putlist':
            print("Uploading to DataList")

            print("eventBody: ")
            print(eventBody)

            if not eventBody:
                response = handleReturn(400, "Request Empty.")
                return
            
            response = putList(client, _dataTableName, "PutRequest", eventBody["devicelist"])
        elif str(type_query) == '/data/deletelist':
            print("Deleting from Data List")

            print("eventBody: ")
            print(eventBody)

            if not eventBody:
                response = handleReturn(400, "Request Empty.")
                return
            
            response = deleteList(client, _dataTableName, "DeleteRequest", eventBody["devicelist"])
        elif str(type_query) == '/data/adduserlist':
            print("Uploading to User List")

            print("eventBody: ")
            print(eventBody)

            if not eventBody:
                response = handleReturn(400, "Request Empty.")
                return
            
            response = putList(client, _permissionTableName, "PutRequest", eventBody["userlist"])
        elif str(type_query) == '/data/deleteuserlist':
            print("Deleting from User List")

            print("eventBody: ")
            print(eventBody)

            if not eventBody:
                response = handleReturn(400, "Request Empty.")
                return
            
            response = deleteList(client, _permissionTableName, "DeleteRequest", eventBody["userlist"])
        elif str(type_query) == '/data/getuserpermissions':
            print("Getting User Permissions")

            print("eventBody: ")
            print(eventBody)

            if not eventBody:
                response = handleReturn(400, "Request Empty.")
                return
            
            response = getUserPermissions(client, eventBody["username"])
        elif str(type_query) == '/data/getalluserpermissions':
            print("Getting All User Permissions")

            print("eventBody: ")
            print(eventBody)
            
            response = getAllUserPermissions(client)
        else:
            return {
                'statusCode': 404,
                'body': "Not Found"
            }

    except Exception as e:
        return handleReturn(400, str(e))
    
    #print("Total Time Elapsed: " + str(time.perf_counter() - first))
    
    return response
