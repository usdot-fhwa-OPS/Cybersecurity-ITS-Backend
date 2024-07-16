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

response = {
    'statusCode': 200,
    'body': ""
}

_userPoolId = 'us-east-1_R4L2tpqhr'
_clientId = '1cba1vn8dmhfl4qk65hk1pusga'
_policyStoreId = 'JNNEApsQDyKXYRLYpB2yZK'


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


def userLogin(client, userName, userPass):

    body = ""
    try:
        statusCode = 200
        body = client.admin_initiate_auth(
            UserPoolId=_userPoolId,
            ClientId=_clientId,
            AuthFlow='ADMIN_USER_PASSWORD_AUTH',
            AuthParameters={
                'USERNAME': userName,
                'PASSWORD': userPass
            },
        )
    except ClientError as e:
        
        statusCode,body = handleError(e)
    
    return handleReturn(statusCode, body)


def userRefreshToken(client, refreshToken):

    body = ""
    try:
        statusCode = 200
        body = client.admin_initiate_auth(
            UserPoolId=_userPoolId,
            ClientId=_clientId,
            AuthFlow='REFRESH_TOKEN_AUTH',
            AuthParameters={
                'REFRESH_TOKEN': refreshToken
            },
        )
    except ClientError as e:
        
        statusCode,body = handleError(e)
    
    return handleReturn(statusCode, body)


def userLogout(client, userName):

    try:
        statusCode = 200
        body = client.admin_user_global_sign_out(
            UserPoolId = _userPoolId,
            Username = userName
        )
    except ClientError as e:
        
        statusCode,body = handleError(e)
    
    return handleReturn(statusCode, body)


def getUserList(client):

    try:
        statusCode = 200
        body = client.list_users(
            UserPoolId = _userPoolId,
        )
    except ClientError as e:
        
        statusCode,body = handleError(e)
    
    return handleReturn(statusCode, body)


def userSignUp(client, username, password, attributes):
    
    try:
        attributes.append(
            {
                "Name": "custom:usergroup",
                "Value": "Users"
            }
        )

        statusCode = 200
        body = client.sign_up(
            ClientId=_clientId,
            Username=username,
            Password=password,
            UserAttributes=
                attributes
        )
        
        body = client.admin_add_user_to_group(
            UserPoolId=_userPoolId,
            Username=username,
            GroupName="Users"
        )
        
    except ClientError as e:
        
        statusCode,body = handleError(e)
    
    return handleReturn(statusCode, body)


def userSetAdmin(client, username, admin):
    
    statusCode = 200
    body = ""
    try:
        if (admin):
            body = client.admin_add_user_to_group(
                UserPoolId=_userPoolId,
                Username=username,
                GroupName="Admin"
            )

            userUpdateAttr(client, username, [{
                "Name": "custom:usergroup",
                "Value": "Admin"
            }])
        else:
            body = client.admin_remove_user_from_group(
                UserPoolId=_userPoolId,
                Username=username,
                GroupName="Admin"
            )

            userUpdateAttr(client, username, [{
                "Name": "custom:usergroup",
                "Value": "Users"
            }])
        
    except ClientError as e:
        
        statusCode,body = handleError(e)
    
    return handleReturn(statusCode, body)


def userConfirmSignUp(client, username, confirmationcode):

    try:
        statusCode = 200
        body = client.confirm_sign_up(
            ClientId=_clientId,
            Username=username,
            ConfirmationCode=confirmationcode,
        )
        
    except ClientError as e:
        
        statusCode,body = handleError(e)
    
    return handleReturn(statusCode, body)


def userConfirmForgotPassword(client, username, password, confirmationcode):

    try:
        statusCode = 200
        body = client.confirm_forgot_password(
            ClientId=_clientId,
            Username=username,
            ConfirmationCode=confirmationcode,
            Password=password
        )
        
    except ClientError as e:
        
        statusCode,body = handleError(e)
    
    return handleReturn(statusCode, body)


def userResetPassword(client, username):

    try:
        statusCode = 200
        body = client.admin_reset_user_password(
            UserPoolId=_userPoolId,
            Username=username
        )
        
    except ClientError as e:
        
        statusCode,body = handleError(e)
    
    return handleReturn(statusCode, body)


def userDelete(client, username):

    try:
        statusCode = 200
        body = client.admin_delete_user(
            UserPoolId = _userPoolId,
            Username=username,
        )
    except ClientError as e:
        
        statusCode,body = handleError(e)
    
    return handleReturn(statusCode, body)


def userEnable(client, username, enabled):

    try:
        statusCode = 200

        if (enabled):
            body = client.admin_enable_user(
                UserPoolId=_userPoolId,
                Username=username
            )
        else:
            body = client.admin_disable_user(
                UserPoolId=_userPoolId,
                Username=username
            )
    except ClientError as e:
        
        statusCode,body = handleError(e)
    
    return handleReturn(statusCode, body)


def userUpdateAttr(client, username, attributes):

    try:
        statusCode = 200
        body = client.admin_update_user_attributes(
            UserPoolId = _userPoolId,
            Username=username,
            UserAttributes=
                attributes
        )
    except ClientError as e:
        
        statusCode,body = handleError(e)
    
    return handleReturn(statusCode, body)


def userAuthChallenge(client, challengeName, challengeResponse, session):

    try:
        statusCode = 200
        body = client.admin_respond_to_auth_challenge(
            UserPoolId=_userPoolId,
            ClientId=_clientId,
            ChallengeName=challengeName,
            ChallengeResponses=challengeResponse,
            Session=session
        )
    except ClientError as e:
        
        statusCode,body = handleError(e)
    
    return handleReturn(statusCode, body)


def userGetVerificationCode(client, accesstoken, attribute):

    try:
        statusCode = 200
        body = client.get_user_attribute_verification_code(
            AccessToken=accesstoken,
            AttributeName=attribute
        )
    except ClientError as e:
        
        statusCode,body = handleError(e)
    
    return handleReturn(statusCode, body)


def userVerifyAttribute(client, accesstoken, attribute, confirmationcode):

    try:
        statusCode = 200
        body = client.verify_user_attribute(
            AccessToken=accesstoken,
            AttributeName=attribute,
            Code=confirmationcode
        )
    except ClientError as e:
        
        statusCode,body = handleError(e)
    
    return handleReturn(statusCode, body)


def checkUserAuthLevel(groups, action):
    print("Checking Auth")

    try:
        client = boto3.client('verifiedpermissions')
        print("After Client")

        if (isinstance(groups, str)):
            print("Is String Group")
            groups = groups.split(',')
            print(groups)
            
        print("After Split")
        print(_policyStoreId)
        print("After Policy")

        for group in groups:
            print("_policyStoreId: ")
            print(_policyStoreId)
            
            body = client.is_authorized(
                policyStoreId=_policyStoreId,
                principal={
                    'entityType': 'ocs_DevPool::Group',
                    'entityId': group
                },
                action={
                    'actionType': 'userFunctions_ocs::Action',
                    'actionId': action
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


def lambda_handler(event, context):
    # TODO implement

    first = time.perf_counter()
    
    print("User Call: ")
    print(event)

    try:
        print("Checking against known Endpoints.")
        type_query = event["resource"]
        
        print("Time Elapsed: Before Json:  " + str(time.perf_counter() - first))
        
        if event["httpMethod"] != "GET":
            if isinstance(event["body"], dict):
                print("Check if Body is dict. True")
                eventBody = event["body"]
            elif event["body"] == None:
                print("Body is Empty.")
                eventBody= {}
            else:
                eventBody = json.loads(event["body"])
                print("Time Elapsed: After jsonLoads:  " + str(time.perf_counter() - first))
        
        client = boto3.client('cognito-idp')
        
        print("Time Elapsed: Before Authorizer:  " + str(time.perf_counter() - first))

        if "authorizer" in event["requestContext"]:
            group = event["requestContext"]["authorizer"]["claims"]["cognito:groups"]
            response = checkUserAuthLevel(group, type_query)

            if (response):
                print("ERROR!")
                return response
        
        print("Time Elapsed: After Authorizer:  " + str(time.perf_counter() - first))

        if str(type_query) == '/user/login':
            print("User Login")

            if not eventBody:
                response = handleReturn(400, "Request Empty.")
                return
            
            response = userLogin(client, eventBody["username"], eventBody["password"])
        elif str(type_query) == '/user/logout':
            print("User Logout")
            
            response = userLogout(client, eventBody["username"])
        elif str(type_query) == '/user/createuser':
            print("User Signup")
            
            print("eventBody: ")
            print(eventBody)

            if not eventBody:
                response = handleReturn(400, "Request Empty.")
                return

            response = userSignUp(client, eventBody["username"], eventBody["password"], eventBody["attributes"])
        elif str(type_query) == '/user/usersetadmin':
            print("User Set Admin")

            if not eventBody:
                response = handleReturn(400, "Request Empty.")
                return
            
            response = userSetAdmin(client, eventBody["username"], eventBody["admin"])
        elif str(type_query) == '/user/refreshtoken':
            print("User Refresh Token")

            if not eventBody:
                response = handleReturn(400, "Request Empty.")
                return
            
            response = userRefreshToken(client, eventBody["refreshtoken"])
        elif str(type_query) == '/user/confirmuser':
            print("User Confirm Account")

            if not eventBody:
                response = handleReturn(400, "Request Empty.")
                return
            
            response = userConfirmSignUp(client, eventBody["username"], eventBody["confirmationcode"])
        elif str(type_query) == '/user/confirmforgotpassword':
            print("User Confirm Forgot Password")

            if not eventBody:
                response = handleReturn(400, "Request Empty.")
                return
            
            response = userConfirmForgotPassword(client, eventBody["username"], eventBody["password"], eventBody["confirmationcode"])
        elif str(type_query) == '/user/resetpassword':
            print("User Reset Password")

            if not eventBody:
                response = handleReturn(400, "Request Empty.")
                return
            
            response = userResetPassword(client, eventBody["username"])
        elif str(type_query) == '/user/enableuser':
            print("User Enable")

            if not eventBody:
                response = handleReturn(400, "Request Empty.")
                return
            
            response = userEnable(client, eventBody["username"], eventBody["enabled"])
        elif str(type_query) == '/user/deleteuser':
            print("User Delete")

            if not eventBody:
                response = handleReturn(400, "Request Empty.")
                return
            
            response = userDelete(client, eventBody["username"])
        elif str(type_query) == '/user/modifyattributes':
            print("Modify User Atributes")

            if not eventBody:
                response = handleReturn(400, "Request Empty.")
                return
            
            response = userUpdateAttr(client, eventBody["username"], eventBody["attributes"])
        elif str(type_query) == '/user/userauthchallenge':
            print("User Authenticate Challenge")

            if not eventBody:
                response = handleReturn(400, "Request Empty.")
                return
            
            response = userAuthChallenge(client, eventBody["challengename"], eventBody["challengeresponse"], eventBody["session"])
        elif str(type_query) == '/user/getverificationcode':
            print("Get Verification Code")

            if not eventBody:
                response = handleReturn(400, "Request Empty.")
                return
            
            response = userGetVerificationCode(client, eventBody["accesstoken"], eventBody["attribute"])
        elif str(type_query) == '/user/verifyattribute':
            print("Verify User Atributes")

            if not eventBody:
                response = handleReturn(400, "Request Empty.")
                return
            
            response = userVerifyAttribute(client, eventBody["accesstoken"], eventBody["attribute"], eventBody["confirmationcode"])
        elif str(type_query) == '/user/getuserlist':
            print("User Get User List")
            
            response = getUserList(client)
        else:
            return {
                'statusCode': 404,
                'body': "Not Found"
            }

    except Exception as e:
        return handleReturn(400, str(e))
    
    print("Total Time Elapsed: " + str(time.perf_counter() - first))
    
    return response
