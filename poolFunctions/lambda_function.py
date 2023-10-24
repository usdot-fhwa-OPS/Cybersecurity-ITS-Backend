import json
import boto3
import time
from botocore.exceptions import ClientError
from boto3.dynamodb.types import TypeDeserializer
from boto3.dynamodb.types import TypeSerializer

_permissionTableName = 'ocsUserPermissions'
_regionName = "us-east-1"

_retryDelay = 2

serializer = TypeSerializer()

def addPermisions(client, tableName, command, dataListRaw):
    dataList = {}
    for device in dataListRaw:
        dataList.update({k: serializer.serialize(v) for k,v in device.items()})

    print("dataList: ")
    print(dataList)

    body = ""
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
        
        print("Error adding permissions: ")
        print(e)
    
    return

def lambda_handler(event, context):

    print("Event: ")
    print(event)

    try:
        print(event["userName"])
        
        client = boto3.client("dynamodb")

        data = {
            "username": event["userName"],
            "permissions": []
        }

        addPermisions(client, _permissionTableName, "PutRequest", [data])
    except ClientError as e:
        print("Error: ")
        print(e)

    # Confirm the user
    event['response']['autoConfirmUser'] = True

    # Set the email as verified if it is in the request
    if 'email' in event['request']['userAttributes']:
        event['response']['autoVerifyEmail'] = True

    # Set the phone number as verified if it is in the request
    if 'phone_number' in event['request']['userAttributes']:
        event['response']['autoVerifyPhone'] = True
    
    return event
