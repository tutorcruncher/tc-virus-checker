import hashlib
import hmac
import json
import logging
import os
import re
import subprocess
from contextlib import asynccontextmanager
from pathlib import Path
from secrets import compare_digest

import boto3
import logfire
import sentry_sdk
from botocore.exceptions import ClientError
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from sentry_sdk.integrations.logging import LoggingIntegration
from starlette.responses import FileResponse

from .settings import Settings

settings = Settings()
logger = logging.getLogger('tcav')
Path('tmp').mkdir(exist_ok=True)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # In production Render hosts the app behind a plain uvicorn process; nothing else
    # starts clamd or keeps signatures fresh. freshclam -d runs as a daemon and checks
    # for signature updates every few hours; clamd exposes the scanning socket used by
    # clamdscan. Skipped in dev/test where clamd is usually started by the OS/service.
    if settings.live:
        logger.info('Starting freshclam daemon and clamd')
        subprocess.Popen(['freshclam', '-d'])
        subprocess.Popen(['clamd'])
    yield


tc_av_app = FastAPI(lifespan=lifespan)

if settings.sentry_dsn:
    sentry_sdk.init(
        dsn=settings.sentry_dsn,
        environment=settings.environment,
        # Breadcrumbs for INFO+, capture warnings and above as Sentry events.
        integrations=[LoggingIntegration(level=logging.INFO, event_level=logging.WARNING)],
    )

if settings.logfire_token:
    logfire.configure(
        token=settings.logfire_token,
        environment=settings.environment,
        service_name='tc-virus-checker',
        scrubbing=False,
    )
    logfire.instrument_fastapi(tc_av_app)
    # Forward stdlib logging (logger.info/warning/error) to Logfire.
    logger.addHandler(logfire.LogfireLoggingHandler())
    logger.setLevel(logging.INFO)


@tc_av_app.get('/')
async def index():
    return {'message': "Welcome to TutorCruncher's virus checker"}


@tc_av_app.get('/robots.txt')
async def robots():
    return FileResponse(path='src/robots.txt', media_type='text/plain')


class DocumentRequest(BaseModel):
    bucket: str
    key: str
    signature: str

    @property
    def payload(self) -> bytes:
        return json.dumps({'bucket': self.bucket, 'key': self.key}).encode()


def _object_is_deleted(s3_client, bucket: str, key: str) -> bool:
    """Return True if the object has been deleted (delete marker or missing)."""
    try:
        s3_client.head_object(Bucket=bucket, Key=key)
    except ClientError as e:
        error_code = e.response.get('Error', {}).get('Code')
        return error_code in ('NoSuchKey', '404', 'NotFound')
    return False


def _check_file(file_path: str, key: str) -> tuple[list, str]:
    if settings.live:
        cmd = f'clamdscan {file_path}'
    else:
        cmd = f'clamdscan --fdpass {file_path}'
    output = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE).stdout.decode()
    tags = []
    try:
        virus_msg = re.search(rf'{file_path}: (.*?)\n', output).group(1)  # ty: ignore[unresolved-attribute]
    except AttributeError:
        logger.error('No virus msg found in output, file_path: "%s", output: "%s"', file_path, output)
        status = 'error'
    else:
        if virus_msg == 'OK':
            logger.info('File %s checked and is clean. Tagging file with status=clean in AWS.', key)
            tags = [{'Key': 'status', 'Value': 'clean'}]
            status = 'clean'
        else:
            logger.info(
                'Virus "%s" discovered when checking %s. Tagging file with status=infected in AWS.', virus_msg, key
            )
            tags = [{'Key': 'status', 'Value': 'infected'}, {'Key': 'virus_name', 'Value': virus_msg}]
            status = 'infected'
    return tags, status


@tc_av_app.post('/check/')
async def check_document(data: DocumentRequest):
    assert settings.shared_secret_key, 'SHARED_SECRET_KEY is not set'
    assert settings.aws_access_key_id, 'AWS_ACCESS_KEY_ID is not set'
    assert settings.aws_secret_access_key, 'AWS_SECRET_KEY is not set'
    payload_sig = hmac.new(settings.shared_secret_key.encode(), data.payload, hashlib.sha1).hexdigest()
    if not compare_digest(payload_sig, data.signature):
        raise HTTPException(status_code=403, detail='Invalid signature')
    s3_client = boto3.client(
        's3',
        aws_access_key_id=settings.aws_access_key_id,
        aws_secret_access_key=settings.aws_secret_access_key,
    )
    file_path = f'tmp/{data.key.replace("/", "-")}'
    s3_client.download_file(Bucket=data.bucket, Key=data.key, Filename=file_path)

    tags, status = _check_file(file_path, data.key)
    if tags:
        try:
            s3_client.put_object_tagging(Bucket=data.bucket, Key=data.key, Tagging={'TagSet': tags})
        except ClientError as e:
            # Tagging a delete marker (object deleted in a versioned bucket between download and
            # tagging) raises MethodNotAllowed. Confirm the object really is gone; otherwise re-raise.
            if not _object_is_deleted(s3_client, data.bucket, data.key):
                raise
            logger.warning('Object %s was deleted before it could be tagged: %s', data.key, e)
            status = f'{status}-untagged'
    try:
        os.remove(file_path)
    except FileNotFoundError:
        status = 'File not found'
    return {'status': status}


@tc_av_app.get('/health/')
async def health():
    result = subprocess.run(['clamdscan', '--ping', '1'], capture_output=True)
    if result.returncode != 0:
        raise HTTPException(status_code=503, detail='clamd is not responding')
    return {'status': 'ok'}
