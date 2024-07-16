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
# read and write objects from/to AWS S3 Bucket "itsconfigurations". This role also gives KMS permissions to encrypt/decrypt data from S3. This role should be
# assigned to any lambda function that interacts with AWS S3. 

import json 
import sys
import boto3
import jsonschema
from botocore.vendored import requests
from botocore.exceptions import ClientError
# Imports library uploaded via lambda layer to validate json

print('Loading Function')

# API Endpoint would be webapp page 

s3 = boto3.client('s3')
bucket = "ocs-test-bucket"


# Overwrite existing configurations with new changes 
def owConf(update):
    json_object = json.dumps(update, indent = 4) 
    fileName = 'data' + '.json'
    uploadByteStream = bytes(json_object.encode('UTF-8'))
    s3.put_object(Bucket = bucket, Key = fileName, Body = uploadByteStream)
    

# Param should be file to validate 
def validateJson(fileName):
    # Gets json and schema from S3 Bucket "itsconfigurations"
    # ListBucket permission must be assigned in iAM role policies for S3 bucket roles in order for NoSuchKey error to be returned when object is not in bucket 
    try:
        responseFile = s3.get_object(Bucket=bucket, Key= fileName + ".json")
    except ClientError as e:
        if e.response['Error']['Code'] == "NoSuchKey":
            return("The object to be validated does not exist in this database.")
    responseSchema = s3.get_object(Bucket=bucket, Key='single_device_schema.txt')

    # Read bodies of json, schema, pulled from s3 
    fileToValidate = responseFile['Body'].read()
    schema = responseSchema['Body'].read()
    
    # Loads pulled json, schema as json file
    json_object_validate = json.loads(fileToValidate)
    json_schema = json.loads(schema) 

    
    # Validate pulled json file against cloud-defined schema 
    try:
        validate(instance=json_object_validate, schema=json_schema)
    except jsonschema.exceptions.ValidationError:
        validator = jsonschema.Draft7Validator(json_schema)
        errors = validator.iter_errors(json_object_validate)
        error_str = ""
        for error in errors:
            print(error)
            print("------")
        s3.delete_object(Bucket = bucket, Key=fileName + ".json")
        return("Invalid JSON file was uploaded. Now deleting from S3...")
    
    

# Takes device to be added (dict) and appends to database 
def addConf(database, title, model, indexDevice):
    newDevice = {
        "title" : title,
        "model" : model,
    }
    # Make a copy of existing configuration list to reupload to S3
    update = database 
    # Append new device to end of list for that device
    update[indexDevice]['vendor'].insert(len(update[indexDevice]['vendor']), newDevice)
    owConf(update)
    

# Delete device configuration   
def deleteConf(indexDevice, database, indexVendor):
    # Make a copy of existing configuration list to reupload to S3 
    update = database
    # Delete corresponding device & configuration - update[device]['vendor'][vendorName]
    del update[indexDevice]['vendor'][indexVendor]
    owConf(update)

 

## Pass in event (dict), 
def lambda_handler(event, context):
    s3_resource = boto3.resource('s3')
    objects = list(s3_resource.Bucket(bucket).objects.filter(Prefix=''))
    print(objects)

    

    responseObject = {}
    responseObject['statusCode'] = 200
    responseObject['headers'] = {}
    responseObject['headers']['Content-Type'] = 'application/json'
    responseObject['body'] = {'BucketContents': len(objects)}
    
    return responseObject