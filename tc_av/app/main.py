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
from starlette.responses import FileResponse

from .settings import Settings

tc_av_app = FastAPI()
settings = Settings()

logger = logging.getLogger('tcav')
try:
    os.mkdir('tmp')
except FileExistsError:
    pass


if dsn := settings.raven_dsn:
    sentry_sdk.init(dsn=dsn)
    tc_av_app.add_middleware(SentryAsgiMiddleware)


@tc_av_app.get('/')
async def index():
    return {'message': "Welcome to TutorCruncher's virus checker"}


@tc_av_app.get('/robots.txt')
async def robots():
    return FileResponse(path='tc_av/robots.txt', media_type='text/plain')


class DocumentRequest(BaseModel):
    bucket: str
    key: str
    signature: str

    @property
    def payload(self):
        return json.dumps({'bucket': self.bucket, 'key': self.key}).encode()


@tc_av_app.post('/check/')
async def check_document(data: DocumentRequest):
    payload_sig = hmac.new(settings.shared_secret_key.encode(), data.payload, hashlib.sha1).hexdigest()
    if not compare_digest(payload_sig, data.signature):
        raise HTTPException(status_code=403, detail='Invalid signature')
    if settings.aws_secret_access_key and settings.aws_access_key_id:
        s3_client = boto3.client(
            's3', aws_access_key_id=settings.aws_access_key_id, aws_secret_access_key=settings.aws_secret_access_key
        )
    else:
        return {'error': 'Env variables aws_access_key_id and aws_secret_access_key is unset'}
    file_path = f'tmp/{data.key.replace("/", "-")}'
    s3_client.download_file(Bucket=data.bucket, Key=data.key, Filename=file_path)

    if settings.live:
        cmd = f'clamdscan {file_path}'
    else:
        cmd = f'clamdscan --fdpass {file_path}'
    output = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE).stdout.decode()

    try:
        virus_msg = re.search(fr'{file_path}: (.*?)\n', output).group(1)
    except AttributeError:
        logger.error('No virus msg found in output, file_path: "%s", output: "%s"', file_path, output)
        status = 'error'
    else:
        if virus_msg == 'OK':
            logger.info('File %s checked and is clean. Tagging file with status=clean in AWS.', data.key)
            tags = [{'Key': 'status', 'Value': 'clean'}]
            status = 'clean'
        else:
            logger.info(
                'Virus "%s" discovered when checking %s. Tagging file with status=infected in AWS.', virus_msg, data.key
            )
            tags = [{'Key': 'status', 'Value': 'infected'}, {'Key': 'virus_name', 'Value': virus_msg}]
            status = 'infected'
        s3_client.put_object_tagging(Bucket=data.bucket, Key=data.key, Tagging={'TagSet': tags})
    try:
        os.remove(file_path)
    except FileNotFoundError:
        status = 'File not found'
    finally:
        return {'status': status}


@tc_av_app.get('/health/')
async def health():
    output = subprocess.run('systemctl status clamav-daemon', shell=True, stdout=subprocess.PIPE).stdout.decode()
    return {'status': output}
