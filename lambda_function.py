import os
import re
import sys
import csv
import gzip
import json
import boto3
from datetime import datetime
from urllib import parse

# 다운받은 패키지를 적용하기 위해서 설정
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'packages'))

from elasticsearch import Elasticsearch, RequestsHttpConnection
from elasticsearch import helpers
from aws_requests_auth.aws_auth import AWSRequestsAuth


# JSON 파일을 읽어서 전역 변수로 자동 생성
for filename in os.listdir('json'):
    if filename.split('.')[0]:
        with open('json/{}'.format(filename), 'r') as json_file:
            globals()['{}_INFO'.format(filename.split('.')[0].upper())] = json.load(json_file)


# Genarate auth request to connect AWS Service
def sts_getauth(role_arn, role_session_name):
    creds = boto3.client('sts').assume_role(
        RoleArn=role_arn,
        RoleSessionName=role_session_name
    )

    return {
        'access_key': creds['Credentials']['AccessKeyId'],
        'secret_key': creds['Credentials']['SecretAccessKey'],
        'session_token': creds['Credentials']['SessionToken']
    }


# the main function for running Lambda
def lambda_handler(event, context):
    # Init payload
    payload = "Skip the event of abnormal."
  
    for record in event.get('Records'):
        s3_event = json.loads(record['body'])

        for body_record in s3_event.get('Records'):
            object_bucket = body_record['s3']['bucket']['name']
            object_key = body_record['s3']['object']['key']

            # get CloudFront ID
            cf_id = object_key.split('/')[0]

            # Unknown CloudFront
            if cf_id not in globals()['PATTERN_INFO']['cf_dict']:
                break

            # get a credential token for S3 by assume role
            s3_auth = sts_getauth(os.environ['s3_role_arn'], 'cross_account_for_lambda')

            # create client session for S3
            s3_client = boto3.client(
                's3',
                aws_access_key_id=s3_auth['access_key'],
                aws_secret_access_key=s3_auth['secret_key'],
                aws_session_token=s3_auth['session_token'],
            )

            # Object file location information
            local_filepath = "/tmp/" + os.path.basename(object_key)

            # Object download from S3
            s3_client.download_file(object_bucket, object_key, local_filepath)

            # parse logfile to record_set
            record_set = []
            record_set_append = record_set.append
            with gzip.open(local_filepath, 'rt') as data:
                result = csv.DictReader(data, fieldnames=globals()['FIELD_INFO']['cloudfront_standardlog_field'], dialect="excel-tab")

                # parse the log file into a dict
                for idx, row in enumerate(result):
                    # skip header row
                    if idx > 1:
                        # CloudFront events are logged to the second only, date and time are seperate
                        # fields which we remove and merge into a new timestamp field
                        date = row.pop('logdate')
                        row['timestamp'] = datetime.strptime(date + " " + row.pop('logtime'), '%Y-%m-%d %H:%M:%S').isoformat()

                        # type change
                        if row['c-port']:
                            try:
                                row['c-port'] = int(row['c-port'])
                            except ValueError:
                                row['c-port'] = 0

                        if row['cs-bytes']:
                            try:
                                row['cs-bytes'] = int(row['cs-bytes'])
                            except ValueError:
                                row['cs-bytes'] = 0

                        if row['sc-bytes']:
                            try:
                                row['sc-bytes'] = int(row['sc-bytes'])
                            except ValueError:
                                row['sc-bytes'] = 0

                        if row['sc-content-len']:
                            try:
                                row['sc-content-len'] = int(row['sc-content-len'])
                            except ValueError:
                                row['sc-content-len'] = 0

                        if row['time-taken']:
                            try:
                                row['time-taken'] = float(row['time-taken'])
                            except ValueError:
                                row['time-taken'] = 0

                        if row['time-to-first-byte']:
                            try:
                                row['time-to-first-byte'] = float(row['time-to-first-byte'])
                            except ValueError:
                                row['time-to-first-byte'] = 0

                        if row['x-host-header']:
                            for k, v in pattern_info.host_dict.items():
                                if re.compile(k).search(row['x-host-header']):
                                    row['stb-type'] = v
                                    break

                        if row['cs-uri-stem'] and row['cs-uri-query']:
                            uri = row['cs-uri-stem']
                            query = parse.unquote(parse.unquote(parse.unquote(row['cs-uri-query'])))

                        # add to new record dict
                        record = {
                            "_index": "-".join([os.environ['es_index_prefix'], date]),
                            "_type": "logs",
                            "_source": row
                        }

                        # append to recordset
                        record_set_append(record)

            # get a credential token for ES by assume role
            es_auth = sts_getauth(os.environ['sts_role_arn'], os.environ['sts_session_name'])
            es_host = os.environ['es_host']

            # create client session for ES
            es_client = Elasticsearch(
                host=es_host,
                scheme="https",
                port=443,
                http_auth=AWSRequestsAuth(
                    aws_host=es_host,
                    aws_region=os.environ['es_region'],
                    aws_service='es',
                    aws_access_key=es_auth['access_key'],
                    aws_secret_access_key=es_auth['secret_key'],
                    aws_token=es_auth['session_token']
                ),
                timeout=int(os.environ['es_connection_timeout']),
                max_retries=10,
                retry_on_timeout=True,
                connection_class=RequestsHttpConnection
            )

            # write the data set to ES, chunk size has been increased to improve performance
            payload = helpers.bulk(
                es_client,
                record_set,
                chunk_size=int(os.environ['es_bulk_chunk_size']),
                timeout=os.environ['es_bulk_timeout'] + "s",
                max_retries=10
            )

            # Lambda Memory 관리를 위한 tmp 디렉토리 삭제
            os.remove(local_filepath)

    return {'statusCode': 200, 'body': payload}
