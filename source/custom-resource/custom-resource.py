######################################################################################################################
#  Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.                                           #
#                                                                                                                    #
#  Licensed under the Apache License, Version 2.0 (the "License"). You may not use this file except in compliance    #
#  with the License. A copy of the License is located at                                                             #
#                                                                                                                    #
#      http://www.apache.org/licenses/LICENSE-2.0                                                                    #
#                                                                                                                    #
#  or in the "license" file accompanying this file. This file is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES #
#  OR CONDITIONS OF ANY KIND, express or implied. See the License for the specific language governing permissions    #
#  and limitations under the License.                                                                                #
######################################################################################################################

import boto3
import botocore
import json
import logging
import math
import time
import datetime
import requests
from urllib.request import Request, urlopen
from os import environ
from botocore.config import Config
from backoff import on_exception, expo

logging.getLogger().debug('Loading function')

#======================================================================================================================
# Constants
#======================================================================================================================
API_CALL_NUM_RETRIES = 5
LIST_LIMIT  = 50
BATCH_DELETE_LIMIT = 500
DELAY_BETWEEN_DELETES = 2
RULE_SUFIX_RATE_BASED = "-HTTP Flood Rule"

waf_client = boto3.client(environ['API_TYPE'], config=Config(retries={'max_attempts': API_CALL_NUM_RETRIES}))

#======================================================================================================================
# Configure Access Log Bucket
#======================================================================================================================
#----------------------------------------------------------------------------------------------------------------------
# Create a bucket (if not exist) and configure an event to call Log Parser lambda funcion when new Access log file is
# created (and stored on this S3 bucket).
#
# This function can raise exception if:
# 01. A empty bucket name is used
# 02. The bucket already exists and was created in a account that you cant access
# 03. The bucket already exists and was created in a different region.
#     You can't trigger log parser lambda function from another region.
#
# All those requirements are pre-verified by helper function.
#----------------------------------------------------------------------------------------------------------------------
def configure_s3_bucket(region, bucket_name):
    logging.getLogger().debug("[configure_s3_bucket] Start")

    if bucket_name.strip() == "":
        raise Exception('Failed to configure access log bucket. Name cannot be empty!')

    #------------------------------------------------------------------------------------------------------------------
    # Create the S3 bucket (if not exist)
    #------------------------------------------------------------------------------------------------------------------
    s3_client = boto3.client('s3')
    try:
        s3_client.head_bucket(Bucket=bucket_name)
    except botocore.exceptions.ClientError as e:
        # If a client error is thrown, then check that it was a 404 error.
        # If it was a 404 error, then the bucket does not exist.
        error_code = int(e.response['Error']['Code'])
        if error_code == 404:
            if region == 'us-east-1':
                s3_client.create_bucket(Bucket=bucket_name, ACL='private')
            else:
                s3_client.create_bucket(Bucket=bucket_name, ACL='private', CreateBucketConfiguration={'LocationConstraint': region})

            # Begin waiting for the S3 bucket, mybucket, to exist
            s3_bucket_exists_waiter = s3_client.get_waiter('bucket_exists')
            s3_bucket_exists_waiter.wait(Bucket=bucket_name)

    logging.getLogger().debug("[configure_s3_bucket] End")

#----------------------------------------------------------------------------------------------------------------------
# Configure bucket event to call Log Parser whenever a new gz log or athena result file is added to the bucket
#----------------------------------------------------------------------------------------------------------------------
def add_s3_bucket_lambda_event(bucket_name, lambda_function_arn, lambda_parser, athena_parser):
    logging.getLogger().debug("[add_s3_bucket_lambda_event] Start")

    s3_client = boto3.client('s3')
    if lambda_function_arn != None and (lambda_parser or athena_parser):
        notification_conf = s3_client.get_bucket_notification_configuration(Bucket=bucket_name)

        new_conf = {}
        new_conf['LambdaFunctionConfigurations'] = []

        if 'TopicConfigurations' in notification_conf:
            new_conf['TopicConfigurations'] = notification_conf['TopicConfigurations']

        if 'QueueConfigurations' in notification_conf:
            new_conf['QueueConfigurations'] = notification_conf['QueueConfigurations']

        if 'LambdaFunctionConfigurations' in notification_conf:
            for lfc in notification_conf['LambdaFunctionConfigurations']:
                for e in lfc['Events']:
                    if "ObjectCreated" in e:
                        if lfc['LambdaFunctionArn'] != lambda_function_arn:
                            new_conf['LambdaFunctionConfigurations'].append(lfc)

        if lambda_parser:
            new_conf['LambdaFunctionConfigurations'].append({
                'Id': 'Call Log Parser',
                'LambdaFunctionArn': lambda_function_arn,
                'Events': ['s3:ObjectCreated:*'],
                'Filter': {'Key': {'FilterRules': [{'Name': 'suffix','Value': 'gz'}]}}
            })

        if athena_parser:
            new_conf['LambdaFunctionConfigurations'].append({
                'Id': 'Call Athena Result Parser',
                'LambdaFunctionArn': lambda_function_arn,
                'Events': ['s3:ObjectCreated:*'],
                'Filter': {'Key': {'FilterRules': [{'Name': 'prefix','Value': 'athena_results/'}, {'Name': 'suffix','Value': 'csv'}]}}
            })

        s3_client.put_bucket_notification_configuration(Bucket=bucket_name, NotificationConfiguration=new_conf)

    logging.getLogger().debug("[add_s3_bucket_lambda_event] End")

#----------------------------------------------------------------------------------------------------------------------
# Clean access log bucket event
#----------------------------------------------------------------------------------------------------------------------
def remove_s3_bucket_lambda_event(bucket_name, lambda_function_arn):
    if lambda_function_arn != None:
        logging.getLogger().debug("[remove_s3_bucket_lambda_event] Start")

        s3_client = boto3.client('s3')
        try:
            new_conf = {}
            notification_conf = s3_client.get_bucket_notification_configuration(Bucket=bucket_name)
            if 'TopicConfigurations' in notification_conf:
                new_conf['TopicConfigurations'] = notification_conf['TopicConfigurations']
            if 'QueueConfigurations' in notification_conf:
                new_conf['QueueConfigurations'] = notification_conf['QueueConfigurations']

            if 'LambdaFunctionConfigurations' in notification_conf:
                new_conf['LambdaFunctionConfigurations'] = []
                for lfc in notification_conf['LambdaFunctionConfigurations']:
                    if lfc['LambdaFunctionArn'] == lambda_function_arn:
                        continue #remove all references for Log Parser event
                    else:
                        new_conf['LambdaFunctionConfigurations'].append(lfc)

            s3_client.put_bucket_notification_configuration(Bucket=bucket_name, NotificationConfiguration=new_conf)

        except Exception as error:
            logging.getLogger().error("Failed to remove S3 Bucket lambda event. Check if the bucket still exists, you own it and has proper access policy.")
            logging.getLogger().error(str(error))

        logging.getLogger().debug("[remove_s3_bucket_lambda_event] End")

#======================================================================================================================
# Configure AWS WAF Logs
#======================================================================================================================
def put_logging_configuration(web_acl_arn, delivery_stream_arn):
    logging.getLogger().debug("[put_logging_configuration] Start")

    waf_client.put_logging_configuration(
        LoggingConfiguration = {
            'ResourceArn': web_acl_arn,
            'LogDestinationConfigs': [delivery_stream_arn]
        }
    )

    logging.getLogger().debug("[put_logging_configuration] End")

def delete_logging_configuration(web_acl_arn):
    logging.getLogger().debug("[delete_logging_configuration] Start")

    waf_client.delete_logging_configuration(ResourceArn = web_acl_arn)

    logging.getLogger().debug("[delete_logging_configuration] End")

#======================================================================================================================
# Populate Reputation List
#======================================================================================================================
def populate_reputation_list(region, reputation_lists_parser_function, reputation_list_set):
    logging.getLogger().debug("[populate_reputation_list] Start")

    try:
        lambda_client = boto3.client('lambda')
        lambda_client.invoke(
            FunctionName=reputation_lists_parser_function.rsplit(":",1)[-1],
            Payload="""{
                  "lists": [
                    {
                        "url": "https://www.spamhaus.org/drop/drop.txt"
                    },
                    {
                        "url": "https://www.spamhaus.org/drop/edrop.txt"
                    },
                    {
                        "url": "https://check.torproject.org/exit-addresses",
                        "prefix": "ExitAddress "
                    },
                    {
                        "url": "https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt"
                    }
                  ],
                  "apiType":"%s",
                  "region":"%s",
                  "ipSetIds": [
                        "%s"
                  ]
                }"""%(environ['API_TYPE'], region, reputation_list_set)
        )

    except Exception as error:
        logging.getLogger().error("[create_stack] Failed to call IP Reputation List function")
        logging.getLogger().error(str(error))

    logging.getLogger().debug("[populate_reputation_list] End")

#======================================================================================================================
# Generate Log Parser Config File
#======================================================================================================================
def generate_app_log_parser_conf_file(stack_name, error_threshold, block_period, app_access_log_bucket, overwrite):
    logging.getLogger().debug("[generate_app_log_parser_conf_file] Start")

    local_file = '/tmp/' + stack_name + '-app_log_conf_LOCAL.json'
    remote_file = stack_name + '-app_log_conf.json'
    default_conf = {
        'general': {
            'errorThreshold': error_threshold,
            'blockPeriod': block_period,
            'errorCodes': ['400', '401', '403', '404', '405']
        },
        'uriList': {
        }
    }

    if not overwrite:
        try:
            s3 = boto3.resource('s3')
            file_obj = s3.Object(app_access_log_bucket, remote_file)
            file_content = file_obj.get()['Body'].read()
            remote_conf = json.loads(file_content)

            if 'general' in remote_conf and 'errorCodes' in remote_conf['general']:
                default_conf['general']['errorCodes'] = remote_conf['general']['errorCodes']

            if 'uriList' in remote_conf:
                default_conf['uriList'] = remote_conf['uriList']

        except Exception as e:
            logging.getLogger().debug("[generate_app_log_parser_conf_file] \tFailed to merge existing conf file data.")
            logging.getLogger().debug(e)

    with open(local_file, 'w') as outfile:
        json.dump(default_conf, outfile)

    s3_client = boto3.client('s3')
    s3_client.upload_file(local_file, app_access_log_bucket, remote_file, ExtraArgs={'ContentType': "application/json"})

    logging.getLogger().debug("[generate_app_log_parser_conf_file] End")

def generate_waf_log_parser_conf_file(stack_name, request_threshold, block_period, waf_access_log_bucket, overwrite):
    logging.getLogger().debug("[generate_waf_log_parser_conf_file] Start")

    local_file = '/tmp/' + stack_name + '-waf_log_conf_LOCAL.json'
    remote_file = stack_name + '-waf_log_conf.json'
    default_conf = {
        'general': {
            'requestThreshold': request_threshold,
            'blockPeriod': block_period,
            'ignoredSufixes': []
        },
        'uriList': {
        }
    }

    if not overwrite:
        try:
            s3 = boto3.resource('s3')
            file_obj = s3.Object(waf_access_log_bucket, remote_file)
            file_content = file_obj.get()['Body'].read()
            remote_conf = json.loads(file_content)

            if 'general' in remote_conf and 'ignoredSufixes' in remote_conf['general']:
                default_conf['general']['ignoredSufixes'] = remote_conf['general']['ignoredSufixes']

            if 'uriList' in remote_conf:
                default_conf['uriList'] = remote_conf['uriList']

        except Exception as e:
            logging.getLogger().debug("[generate_waf_log_parser_conf_file] \tFailed to merge existing conf file data.")
            logging.getLogger().debug(e)

    with open(local_file, 'w') as outfile:
        json.dump(default_conf, outfile)

    s3_client = boto3.client('s3')
    s3_client.upload_file(local_file, waf_access_log_bucket, remote_file, ExtraArgs={'ContentType': "application/json"})

    logging.getLogger().debug("[generate_waf_log_parser_conf_file] End")

#======================================================================================================================
# Auxiliary Functions
#======================================================================================================================
def send_response(event, context, responseStatus, responseData, resourceId, reason=None):
    logging.getLogger().debug("[send_response] Start")

    responseUrl = event['ResponseURL']
    cw_logs_url = "https://console.aws.amazon.com/cloudwatch/home?region=%s#logEventViewer:group=%s;stream=%s"%(context.invoked_function_arn.split(':')[3], context.log_group_name, context.log_stream_name)

    logging.getLogger().info(responseUrl)
    responseBody = {}
    responseBody['Status'] = responseStatus
    responseBody['Reason'] = reason or ('See the details in CloudWatch Logs: ' +  cw_logs_url)
    responseBody['PhysicalResourceId'] = resourceId
    responseBody['StackId'] = event['StackId']
    responseBody['RequestId'] = event['RequestId']
    responseBody['LogicalResourceId'] = event['LogicalResourceId']
    responseBody['NoEcho'] = False
    responseBody['Data'] = responseData

    json_responseBody = json.dumps(responseBody)
    logging.getLogger().debug("Response body:\n" + json_responseBody)

    headers = {
        'content-type' : '',
        'content-length' : str(len(json_responseBody))
    }

    try:
        response = requests.put(responseUrl,
                                data=json_responseBody,
                                headers=headers)
        logging.getLogger().debug("Status code: " + response.reason)

    except Exception as error:
        logging.getLogger().error("[send_response] Failed executing requests.put(..)")
        logging.getLogger().error(str(error))

    logging.getLogger().debug("[send_response] End")

def send_anonymous_usage_data(action_type, resource_properties):

    try:
        if 'SendAnonymousUsageData' not in resource_properties or resource_properties['SendAnonymousUsageData'].lower() != 'yes':
            return
        logging.getLogger().debug("[send_anonymous_usage_data] Start")

        usage_data = {
            "Solution": "SO0006",
            "UUID": resource_properties['UUID'],
            "TimeStamp": str(datetime.datetime.utcnow().isoformat()),
            "Data":
            {
                "Version": "2.3.0",
                "data_type" : "custom_resource",
                "region" : resource_properties['Region'],
                "action" : action_type,
                "sql_injection_protection": resource_properties['ActivateSqlInjectionProtectionParam'],
                "xss_scripting_protection": resource_properties['ActivateCrossSiteScriptingProtectionParam'],
                "http_flood_protection": resource_properties['ActivateHttpFloodProtectionParam'],
                "scanners_probes_protection": resource_properties['ActivateScannersProbesProtectionParam'],
                "reputation_lists_protection": resource_properties['ActivateReputationListsProtectionParam'],
                "bad_bot_protection": resource_properties['ActivateBadBotProtectionParam'],
                "request_threshold": resource_properties['RequestThreshold'],
                "error_threshold": resource_properties['ErrorThreshold'],
                "waf_block_period": resource_properties['WAFBlockPeriod']
            }
        }

        #--------------------------------------------------------------------------------------------------------------
        logging.getLogger().info("[send_anonymous_usage_data] Send Data")
        #--------------------------------------------------------------------------------------------------------------
        url = 'https://metrics.awssolutionsbuilder.com/generic'
        req = Request(url, method='POST', data=bytes(json.dumps(usage_data), encoding='utf8'), headers={'Content-Type': 'application/json'})
        rsp = urlopen(req)
        rspcode = rsp.getcode()
        logging.getLogger().debug('[send_anonymous_usage_data] Response Code: {}'.format(rspcode))
        logging.getLogger().debug("[send_anonymous_usage_data] End")

    except Exception as error:
        logging.getLogger().debug("[send_anonymous_usage_data] Failed to Send Data")
        logging.getLogger().debug(str(error))

#======================================================================================================================
# Lambda Entry Point
#======================================================================================================================
def lambda_handler(event, context):
    responseStatus = 'SUCCESS'
    reason = None
    responseData = {}
    resourceId = event['PhysicalResourceId'] if 'PhysicalResourceId' in event else event['LogicalResourceId']
    result = {
        'StatusCode': '200',
        'Body':  {'message': 'success'}
    }

    try:
        #------------------------------------------------------------------
        # Set Log Level
        #------------------------------------------------------------------
        global log_level
        log_level = str(environ['LOG_LEVEL'].upper())
        if log_level not in ['DEBUG', 'INFO','WARNING', 'ERROR','CRITICAL']:
            log_level = 'ERROR'
        logging.getLogger().setLevel(log_level)

        #----------------------------------------------------------
        # Read inputs parameters
        #----------------------------------------------------------
        logging.getLogger().info(event)
        request_type = event['RequestType'].upper() if ('RequestType' in event) else ""
        logging.getLogger().info(request_type)

        #----------------------------------------------------------
        # Process event
        #----------------------------------------------------------
        if event['ResourceType'] == "Custom::ConfigureAppAccessLogBucket":
            lambda_log_parser_function = event['ResourceProperties']['LogParser'] if 'LogParser' in event['ResourceProperties'] else None
            lambda_parser = True if event['ResourceProperties']['ScannersProbesLambdaLogParser'] == 'yes' else False
            athena_parser = True if event['ResourceProperties']['ScannersProbesAthenaLogParser'] == 'yes' else False

            if 'CREATE' in request_type:
                configure_s3_bucket(event['ResourceProperties']['Region'], event['ResourceProperties']['AppAccessLogBucket'])
                add_s3_bucket_lambda_event(event['ResourceProperties']['AppAccessLogBucket'],
                    lambda_log_parser_function,
                    lambda_parser,
                    athena_parser)

            elif 'UPDATE' in request_type:
                old_lambda_app_log_parser_function = event['OldResourceProperties']['LogParser'] if 'LogParser' in event['OldResourceProperties'] else None
                old_lambda_parser = True if event['OldResourceProperties']['ScannersProbesLambdaLogParser'] == 'yes' else False
                old_athena_parser = True if event['OldResourceProperties']['ScannersProbesAthenaLogParser'] == 'yes' else False

                if (event['OldResourceProperties']['AppAccessLogBucket'] != event['ResourceProperties']['AppAccessLogBucket'] or
                        old_lambda_app_log_parser_function != lambda_log_parser_function or
                        old_lambda_parser != lambda_parser or
                        old_athena_parser != athena_parser):

                    remove_s3_bucket_lambda_event(event['OldResourceProperties']["AppAccessLogBucket"],
                        old_lambda_app_log_parser_function)
                    add_s3_bucket_lambda_event(event['ResourceProperties']['AppAccessLogBucket'],
                        lambda_log_parser_function,
                        lambda_parser,
                        athena_parser)

            elif 'DELETE' in request_type:
                remove_s3_bucket_lambda_event(event['ResourceProperties']["AppAccessLogBucket"],
                    lambda_log_parser_function)

        elif event['ResourceType'] == "Custom::ConfigureWafLogBucket":
            lambda_log_parser_function = event['ResourceProperties']['LogParser'] if 'LogParser' in event['ResourceProperties'] else None
            lambda_parser = True if event['ResourceProperties']['HttpFloodLambdaLogParser'] == 'yes' else False
            athena_parser = True if event['ResourceProperties']['HttpFloodAthenaLogParser'] == 'yes' else False

            if 'CREATE' in request_type:
                add_s3_bucket_lambda_event(event['ResourceProperties']['WafLogBucket'],
                    lambda_log_parser_function,
                    lambda_parser,
                    athena_parser)

            elif 'UPDATE' in request_type:
                old_lambda_app_log_parser_function = event['OldResourceProperties']['LogParser'] if 'LogParser' in event['OldResourceProperties'] else None
                old_lambda_parser = True if event['OldResourceProperties']['HttpFloodLambdaLogParser'] == 'yes' else False
                old_athena_parser = True if event['OldResourceProperties']['HttpFloodAthenaLogParser'] == 'yes' else False

                if (event['OldResourceProperties']['WafLogBucket'] != event['ResourceProperties']['WafLogBucket'] or
                        old_lambda_app_log_parser_function != lambda_log_parser_function or
                        old_lambda_parser != lambda_parser or
                        old_athena_parser != athena_parser):

                    remove_s3_bucket_lambda_event(event['OldResourceProperties']["WafLogBucket"],
                        old_lambda_app_log_parser_function)
                    add_s3_bucket_lambda_event(event['ResourceProperties']['WafLogBucket'],
                        lambda_log_parser_function,
                        lambda_parser,
                        athena_parser)

            elif 'DELETE' in request_type:
                remove_s3_bucket_lambda_event(event['ResourceProperties']["WafLogBucket"],
                    lambda_log_parser_function)

        elif event['ResourceType'] == "Custom::PopulateReputationList":
            if 'CREATE' in request_type or 'UPDATE' in request_type:
                populate_reputation_list(event['ResourceProperties']['Region'],
                    event['ResourceProperties']['ReputationListsParser'],
                    event['ResourceProperties']['WAFReputationListsSet'])

            # DELETE: do nothing

        elif event['ResourceType'] == "Custom::ConfigureAWSWAFLogs":
            if 'CREATE' in request_type:
                put_logging_configuration(event['ResourceProperties']['WAFWebACLArn'],
                    event['ResourceProperties']['DeliveryStreamArn'])

            elif 'UPDATE' in request_type:
                delete_logging_configuration(event['OldResourceProperties']['WAFWebACLArn'])
                put_logging_configuration(event['ResourceProperties']['WAFWebACLArn'],
                    event['ResourceProperties']['DeliveryStreamArn'])

            elif 'DELETE' in request_type:
                delete_logging_configuration(event['ResourceProperties']['WAFWebACLArn'])

        elif event['ResourceType'] == "Custom::GenerateAppLogParserConfFile":
            stack_name = event['ResourceProperties']['StackName']
            error_threshold = int(event['ResourceProperties']['ErrorThreshold'])
            block_period = int(event['ResourceProperties']['WAFBlockPeriod'])
            app_access_log_bucket = event['ResourceProperties']['AppAccessLogBucket']

            if 'CREATE' in request_type:
                generate_app_log_parser_conf_file(stack_name, error_threshold, block_period, app_access_log_bucket, True)
            elif 'UPDATE' in request_type:
                generate_app_log_parser_conf_file(stack_name, error_threshold, block_period, app_access_log_bucket, False)

            # DELETE: do nothing

        elif event['ResourceType'] == "Custom::GenerateWafLogParserConfFile":
            stack_name = event['ResourceProperties']['StackName']
            request_threshold = int(event['ResourceProperties']['RequestThreshold'])
            block_period = int(event['ResourceProperties']['WAFBlockPeriod'])
            waf_access_log_bucket = event['ResourceProperties']['WafAccessLogBucket']

            if 'CREATE' in request_type:
                generate_waf_log_parser_conf_file(stack_name, request_threshold, block_period, waf_access_log_bucket, True)
            elif 'UPDATE' in request_type:
                generate_waf_log_parser_conf_file(stack_name, request_threshold, block_period, waf_access_log_bucket, False)

            # DELETE: do nothing

    except Exception as error:
        logging.getLogger().error(error)
        responseStatus = 'FAILED'
        reason = str(error)
        result = {
            'statusCode': '500',
            'body':  {'message': reason}
        }

    finally:
        #------------------------------------------------------------------
        # Send Result
        #------------------------------------------------------------------
        if 'ResponseURL' in event:
            send_response(event, context, responseStatus, responseData, resourceId, reason)

        return json.dumps(result)
