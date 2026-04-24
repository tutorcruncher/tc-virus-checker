import asyncio
import hashlib
import hmac
import json
import logging
import os
import re
import subprocess
import time
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

from .logs import configure_logging
from .settings import Settings

configure_logging()

settings = Settings()
logger = logging.getLogger('tcav')
Path('tmp').mkdir(exist_ok=True)

CLAMD_CONFIG = 'src/clamd.conf'
CLAMDSCAN_TIMEOUT_S = 60


def _clamdscan_cmd(*args: str) -> list[str]:
    """Build a clamdscan argv. In live mode we point it at our bundled clamd.conf so it
    talks to the clamd we started in the lifespan (which listens on /tmp/clamd.socket)."""
    cmd = ['clamdscan']
    if settings.live:
        cmd.append(f'--config-file={CLAMD_CONFIG}')
    else:
        cmd.append('--fdpass')
    cmd.extend(args)
    return cmd


async def _wait_for_clamd(timeout_s: int = 120) -> None:
    """Poll clamd until --ping succeeds or we hit timeout."""
    for attempt in range(timeout_s):
        try:
            result = subprocess.run(_clamdscan_cmd('--ping', '1'), capture_output=True, timeout=3)
            if result.returncode == 0:
                logger.info('clamd ready after %ds', attempt)
                return
        except subprocess.TimeoutExpired:
            pass
        await asyncio.sleep(1)
    logger.error('clamd did not become ready within %ds', timeout_s)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Fail fast on a misconfigured deploy instead of 500ing on the first request.
    assert settings.shared_secret_key, 'SHARED_SECRET_KEY is not set'
    assert settings.aws_access_key_id, 'AWS_ACCESS_KEY_ID is not set'
    assert settings.aws_secret_access_key, 'AWS_SECRET_KEY is not set'
    if settings.live:
        # Render's plain uvicorn process is the only thing running; we have to start
        # clamd and keep signatures fresh ourselves. freshclam -d polls for DB updates;
        # clamd serves clamdscan over /tmp/clamd.socket (see src/clamd.conf).
        logger.info('Starting freshclam daemon and clamd')
        subprocess.Popen(['freshclam', '-d'])
        subprocess.Popen(['clamd', '-c', CLAMD_CONFIG])
        await _wait_for_clamd()
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
    logger.addHandler(logfire.LogfireLoggingHandler())


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


async def _object_is_deleted(s3_client, bucket: str, key: str) -> bool:
    """Return True if the object has been deleted (delete marker or missing)."""
    try:
        await asyncio.to_thread(s3_client.head_object, Bucket=bucket, Key=key)
    except ClientError as e:
        error_code = e.response.get('Error', {}).get('Code')
        return error_code in ('NoSuchKey', '404', 'NotFound')
    return False


async def _check_file(file_path: str, key: str) -> tuple[list, str]:
    start = time.monotonic()
    try:
        result = await asyncio.to_thread(
            subprocess.run, _clamdscan_cmd(file_path), stdout=subprocess.PIPE, timeout=CLAMDSCAN_TIMEOUT_S
        )
    except subprocess.TimeoutExpired:
        logger.warning('clamdscan timed out on %s after %.2fs', key, time.monotonic() - start)
        return [], 'timeout'
    logger.info('clamdscan on %s took %.2fs', key, time.monotonic() - start)
    output = result.stdout.decode()  # ty: ignore[unresolved-attribute]
    tags = []
    try:
        virus_msg = re.search(rf'{re.escape(file_path)}: (.*?)\n', output).group(1)  # ty: ignore[unresolved-attribute]
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
    await asyncio.to_thread(s3_client.download_file, Bucket=data.bucket, Key=data.key, Filename=file_path)

    tags, status = await _check_file(file_path, data.key)
    if tags:
        try:
            await asyncio.to_thread(
                s3_client.put_object_tagging, Bucket=data.bucket, Key=data.key, Tagging={'TagSet': tags}
            )
        except ClientError as e:
            # Tagging a delete marker (object deleted in a versioned bucket between download and
            # tagging) raises MethodNotAllowed. Confirm the object really is gone; otherwise re-raise.
            if not await _object_is_deleted(s3_client, data.bucket, data.key):
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
    result = await asyncio.to_thread(subprocess.run, _clamdscan_cmd('--ping', '1'), capture_output=True)
    if result.returncode != 0:
        raise HTTPException(status_code=503, detail='clamd is not responding')
    return {'status': 'ok'}
