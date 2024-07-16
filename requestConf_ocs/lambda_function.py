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