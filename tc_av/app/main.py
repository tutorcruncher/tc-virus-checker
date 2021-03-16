import hashlib
import hmac
import json
import logging
import os
import re
import subprocess
from secrets import compare_digest

import boto3
import sentry_sdk
from fastapi import FastAPI, HTTPException
from pydantic.main import BaseModel
from sentry_sdk.integrations.asgi import SentryAsgiMiddleware

from tc_av.app.settings import Settings

tc_av_app = FastAPI()
settings = Settings()

logger = logging.getLogger('tc-av')


if dsn := settings.raven_dsn:
    sentry_sdk.init(dsn=dsn)
    tc_av_app.add_middleware(SentryAsgiMiddleware)


s3_client = boto3.client(
    's3', aws_access_key_id=settings.aws_access_key_id, aws_secret_access_key=settings.aws_secret_access_key
)


@tc_av_app.get('/')
async def index():
    return {'message': "Welcome to TutorCruncher's virus checker"}


class DocumentRequest(BaseModel):
    bucket: str
    key: str
    signature: str

    @property
    def payload(self):
        return json.dumps({'bucket': self.bucket, 'key': self.key}).encode()


@tc_av_app.post('/check/')
async def check_document(data: DocumentRequest):
    payload_sig = hmac.new(settings.tc_secret_key.encode(), data.payload, hashlib.sha1).hexdigest()
    if not compare_digest(payload_sig, data.signature):
        raise HTTPException(status_code=403, detail='Invalid signature')
    file_path = f'tmp/{data.key}'
    s3_client.download_file(Bucket=data.bucket, Key=data.key, Filename=file_path)
    output = subprocess.run(f'clamdscan {file_path}', shell=True, stdout=subprocess.PIPE).stdout.decode()

    virus_msg = re.search(fr'{file_path}: (.*?)\n', output)
    if virus_msg.group(1) == 'OK':
        logger.info('File %s checked and is clean.', data.key)
        tags = [{'Key': 'status', 'Value': 'clean'}]
    else:
        logger.info('Virus "%s" discovered when checking %s. Quarantining file in AWS.', virus_msg, data.key)
        tags = [{'Key': 'status', 'Value': 'infected'}, {'Key': 'virus_name', 'Value': virus_msg}]
    s3_client.put_object_tagging(Bucket=data.bucket, Key=data.key, Tagging={'TagSet': tags})
    os.remove(file_path)
    return {'message': 'OK' if tags['status'] == 'clean' else 'Virus found'}
