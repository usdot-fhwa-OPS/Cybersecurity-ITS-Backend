# In order for this lambda function to operate properly, it has been given the iamRole "its_S3 Role" which allows it to 
# read and write objects from/to AWS S3 Bucket "itsconfigurations". This role should be assigned to any
# lambda function that interacts with AWS S3. 


import json 
import boto3
from botocore.vendored import requests
print('Loading Function')
s3 = boto3.client('s3')


def getConf():
    # Gets configurations from file "data.json" from S3 Bucket "itsconfigurations"
    response = s3.get_object(Bucket='ocs-test-bucket', Key='test_data.json')
    data = response['Body'].read()
    
    return data

def getSchema():
    response = s3.get_object(Bucket='itsconfigurations', Key= file + '.txt')
    data = response['Body'].read()
    
    return data
    
    
def checkApproval ():
    client = boto3.client('verifiedpermissions')

    response = client.is_authorized(
        policyStoreId='JNNEApsQDyKXYRLYpB2yZK',
        principal={
            'entityType': 'Admin',
            'entityId': 'user3'
        },
        action={
            'actionType': 'Action',
            'actionId': 'Data/Request'
        }
    )

    return true

def lambda_handler(event, context):

    print("event")
    print(event)

    responseObject = {}
    responseObject['statusCode'] = 201
    responseObject['headers'] = {}
    responseObject['headers']['Content-Type'] = 'application/json'
    responseObject['body'] = getConf()
    
    return responseObject
    # Status code handling