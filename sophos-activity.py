import boto3
import json
import os
import logging
import requests
from botocore.exceptions import ClientError
from datetime import datetime,timedelta
from utils.helpers import chunks
from utils.dates import utcnow, toUTC
import calendar

logger = logging.getLogger()
logger.setLevel(logging.INFO)

FIREHOSE_DELIVERY_STREAM= os.environ.get('FIREHOSE_DELIVERY_STREAM','test')
FIREHOSE_BATCH_SIZE=os.environ.get('FIREHOSE_BATCH_SIZE',100)
# the api key you get from the sophos cloud console
SOPHOS_API_KEY_NAME=os.environ.get('SOPHOS_API_KEY_NAME','unknown')
# the base64 string you get from the sophos cloud console (the text after 'Basic')
SOPHOS_BASIC_AUTH_STRING_NAME=os.environ.get('SOPHOS_BASIC_AUTH_STRING_NAME','unknown')

# aws/boto resources
ssmclient=boto3.client('ssm')
secrets_manager = boto3.client('secretsmanager')
f_hose = boto3.client('firehose')

def get_parameter(parameter_name,default):
    try:
        return(ssmclient.get_parameter(Name=parameter_name)["Parameter"]['Value'])
    except ClientError as e:
        if e.response['Error']['Code'] == 'ParameterNotFound':
            return default

def put_parameter(parameter_name,value):
    ssmclient.put_parameter(Name=parameter_name,Type='String',Value=value,Overwrite=True)

def send_to_firehose(records):
    # records should be a list of dicts
    if type(records) is list:
        # batch up the list below the limits of firehose
        for batch in chunks(records,FIREHOSE_BATCH_SIZE):
            response = f_hose.put_record_batch(
                DeliveryStreamName=FIREHOSE_DELIVERY_STREAM,
                Records=[{'Data': bytes(str(json.dumps(record)+'\n').encode('UTF-8'))} for record in batch]
            )
            logger.debug('firehose response is: {}'.format(response))

def handler(event,context):
    EVENTS_V1 = '/siem/v1/events'
    ALERTS_V1 = '/siem/v1/alerts'

    ENDPOINTS = [EVENTS_V1,ALERTS_V1]

    NOISY_EVENTTYPES=["Event::Endpoint::UpdateFailure",
                    "Event::Endpoint::UpdateSuccess",
                    "Event::Endpoint::SavDisabled",
                    "Event::Endpoint::SavEnabled",
                    "Event::Endpoint::Enc::DiskEncryptionStatusChanged"]

    exclude_types = ','.join(["%s" % t for t in NOISY_EVENTTYPES])
    exclude_types = 'exclude_types=' + exclude_types

    sophos_api_key = secrets_manager.get_secret_value(SecretId=SOPHOS_API_KEY_NAME)["SecretString"]
    sophos_basic_auth_string = secrets_manager.get_secret_value(SecretId=SOPHOS_BASIC_AUTH_STRING_NAME)["SecretString"]
    url="https://api1.central.sophos.com/gateway"
    last_run_time = utcnow().isoformat()
    records_retrieved = False
    # setup a session
    session = requests.Session()
    session.headers = {'Content-Type': 'application/json; charset=utf-8',
                        'Accept': 'application/json',
                        'X-Locale': 'en',
                        'Authorization': f'Basic {sophos_basic_auth_string}',
                        'x-api-key': sophos_api_key}

    # figure out the last time we checked for records
    since=get_parameter('/sophos-events/lastquerytime',(utcnow()-timedelta(hours=12)).isoformat())
    # 'since' should be an iso formatted utc string
    # sophos wants epoch
    since=int(calendar.timegm((toUTC(since).timetuple())))

    params = {
        'limit': 1000,
        'from_date': since
    }
    for endpoint in ENDPOINTS:
        if 'cursor' in params:
            # rm any cursor left over from the last endpoint
            del params['cursor']
        next_page = True
        while next_page:
            # figure out ending URL like
            # https://api1.central.sophos.com/gateway/siem/v1/events?limit=1000&from_date=1584374987&exclude_types=Event::Endpoint::UpdateFailure,Event::Endpoint::UpdateSuccess,Event::Endpoint::SavDisabled,Event::Endpoint::SavEnabled,Event::Endpoint::Enc::DiskEncryptionStatusChanged
            args = '&'.join(['%s=%s' % (k, v) for k, v in params.items()]+[exclude_types, ])
            events_request_url = '%s%s?%s' % (url, endpoint, args)
            response=session.get(events_request_url)
            result=response.json()
            events=result['items']
            if events:
                logger.info(f"sending: {len(events)} sophos records to firehose")
                send_to_firehose(events)
                records_retrieved = True

            if not result['has_more']:
                next_page=False
            params['cursor'] = result['next_cursor']

    # sometimes activity log lags behind realtime
    # so regardless of the time we request, there won't be records available until later
    # only move the time forward if we received records.
    if records_retrieved:
        put_parameter('/sophos-events/lastquerytime',last_run_time)
