# Copyright (C) 2024 LEIDOS.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may not
# use this file except in compliance with the License. You may obtain a copy of
# the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations under
# the License.

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
_tableName = 'ocsDevTable'
_permissionTableName = 'ocsUserPermissions'
_regionName = "us-east-1"

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


def generateAccessToken(authList):

    parsedList = []

    for auth in authList:
        authRaw = auth.split(":")
        
        if len(authRaw) != 2: return handleReturn(400, "User Permission Error")
        parsedList.append(authRaw[1])

    accessRequest = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "OCSTechAccess",
                "Effect": "Allow",
                "Action": [
                    "dynamodb:GetItem",
                    "dynamodb:Query",
                    "dynamodb:BatchGetItem"
                ],
                "Resource": [
                    "arn:aws:dynamodb:us-east-1:286010155551:table/ocsDevTable",
                    "arn:aws:dynamodb:us-east-1:286010155551:table/ocsDevTable/index/*",
                ],
                "Condition": {
                    "ForAllValues:StringLike": {
                        "dynamodb:LeadingKeys": parsedList
                    }
                }
            }
        ]
    }

    body = ""

    try:
        client = boto3.client("sts")

        statusCode = 200
        body = client.assume_role(
            Policy=json.dumps(accessRequest),
            DurationSeconds=900,
            RoleArn='arn:aws:iam::286010155551:role/dynamoDBBaseRole',
            RoleSessionName='ocsTechAssumedRole',
            ExternalId='ocsUserTech',
        )
        
    except ClientError as e:
        
        statusCode,body = handleError(e)
    
    return statusCode, body


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


def setDBClient(auth):
    session = boto3.Session(
        aws_access_key_id=auth["Credentials"]["AccessKeyId"], 
        aws_secret_access_key=auth["Credentials"]["SecretAccessKey"],
        aws_session_token=auth["Credentials"]["SessionToken"],
        region_name=_regionName
    )
    
    return session.client("dynamodb")


def requestSubset(client, allowedItems):

    body = ""
    statusCode = 200
    rawData = []

    for query in allowedItems:
        try:
            queryRaw = query.split(":")
            if len(queryRaw) != 2: return handleReturn(400, "User Permission Error")

            startKey = {}
            paginate = True
            while paginate:

                if startKey:
                    if queryRaw[0] == "DeviceBrand": 
                        body = client.query(
                            TableName=_tableName,
                        ExclusiveStartKey=startKey,
                            KeyConditionExpression='DeviceBrand = :DeviceBrand',
                            ExpressionAttributeValues={
                                ':DeviceBrand': {'S': queryRaw[1]}
                            }
                        )
                    else:
                        print("DeviceType: ")
                        body = client.query(
                            TableName=_tableName,
                            ExclusiveStartKey=startKey,
                            IndexName="DeviceTypeIndex",
                            KeyConditionExpression= 'DeviceType = :DeviceType',
                            ExpressionAttributeValues={
                                ":DeviceType": {"S": queryRaw[1]}
                            }
                        )
                else:
                    if queryRaw[0] == "DeviceBrand": 
                        body = client.query(
                            TableName=_tableName,
                            KeyConditionExpression='DeviceBrand = :DeviceBrand',
                            ExpressionAttributeValues={
                                ':DeviceBrand': {'S': queryRaw[1]}
                            }
                        )
                    else:
                        print("DeviceType: ")
                        body = client.query(
                            TableName=_tableName,
                            IndexName="DeviceTypeIndex",
                            KeyConditionExpression= 'DeviceType = :DeviceType',
                            ExpressionAttributeValues={
                                ":DeviceType": {"S": "Router"}
                            }
                        )



                bodyParsed = []
                for item in body["Items"]:
                    bodyParsed.append({k: deserializer.deserialize(v) for k,v in item.items()})

                rawData = rawData + bodyParsed

                if "ExclusiveStartKey" in body:
                    startKey = body["ExclusiveStartKey"]
                else:
                    paginate = False

        except ClientError as e:
            
            statusCode,body = handleError(e)
            return handleReturn(statusCode, body)

    body["Items"] = rawData
    
    return handleReturn(statusCode, body)


def requestAll(client):
    
    body = ""
    statusCode = 200
    rawData = []

    try:

        startKey = {}
        paginate = True
        while paginate:
            if startKey:
                body = client.scan(
                    TableName=_tableName,
                    ExclusiveStartKey=startKey
                )
            else:
                body = client.scan(
                    TableName=_tableName
                )

            bodyParsed = []
            for item in body["Items"]:
                bodyParsed.append({k: deserializer.deserialize(v) for k,v in item.items()})

            rawData = rawData + bodyParsed

            if "LastEvaluatedKey" in body:
                startKey = body["LastEvaluatedKey"]
            else:
                paginate = False

    except ClientError as e:
        print("Error")
        
        statusCode,body = handleError(e)
        return handleReturn(statusCode, body)

    body["Items"] = rawData
    
    return handleReturn(statusCode, body)


def requestUserPermissions(username):

    adminClient = boto3.client('dynamodb')

    body = ""
    try:
        statusCode = 200
        body = adminClient.get_item(
            TableName=_permissionTableName,
            Key={
                'username': {
                    'S': username,
                }
            }
        )

        if "Item" in body:
            rawData = body["Item"]

            body = {k: deserializer.deserialize(v) for k,v in rawData.items()}
        else:
            statusCode = 400
            body = ["User is not authorized on any values."]
    except ClientError as e:
        print("requestUserPermissions; Error")
        
        statusCode,body = handleError(e)
        
    return handleReturn(statusCode, body)


def lambda_handler(event, context):
    # TODO implement

    #first = time.perf_counter()
    
    print("User Call: ")
    print(event)
    userPermissionList = []

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
        
        userPermissionResponse = requestUserPermissions(event["requestContext"]["authorizer"]["claims"]["cognito:username"])

        if userPermissionResponse["statusCode"] != 200:
            return userPermissionResponse

        userPermissionRaw = json.loads(userPermissionResponse["body"])
        userPermissionList = userPermissionRaw["permissions"]

        accessTokenRequestCode, accessTokenRequestResponse = generateAccessToken(userPermissionList)

        if accessTokenRequestCode != 200:
            return handleReturn(accessTokenRequestCode, accessTokenRequestResponse)

        client =  setDBClient(accessTokenRequestResponse)

        print("Client Ready:")

        if str(type_query) == '/data/requestall':
            print("Request All")

            client = boto3.client('dynamodb')

            response = requestAll(client)
        elif str(type_query) == '/data/requestuserdevices':
            print("Request All User Devices")
        
            if len(userPermissionList) > 0:
                response = requestSubset(client, userPermissionList)
            else:
                response = handleReturn(400, "User Cannot Access Request Resources.")
        elif str(type_query) == '/data/requestSubset':
            print("Request Subset")

            if not eventBody:
                response = handleReturn(400, "Request Empty.")
                return
            
            userPermissionSet = set(userPermissionList)
            userRequest = set(eventBody["requestlist"])

            approvedList = list(userPermissionSet.intersection(userRequest))
        
            if len(approvedList) > 0:
                response = requestSubset(client, approvedList)
            else:
                response = handleReturn(400, "User Cannot Access Request Resources.")
        else:
            return {
                'statusCode': 404,
                'body': "Endpoint Not Found"
            }

    except Exception as e:
        return handleReturn(400, str(e))
    
    #print("Total Time Elapsed: " + str(time.perf_counter() - first))
    
    return response
