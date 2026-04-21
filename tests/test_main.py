import hashlib
import hmac
import json
import os
import subprocess
from pathlib import Path
from unittest.mock import patch

import boto3
import pytest
from botocore.exceptions import ClientError

from src.app.main import settings


def test_index(client):
    r = client.get('/')
    assert r.status_code == 200
    assert r.json() == {'message': "Welcome to TutorCruncher's virus checker"}


def test_robots(client):
    r = client.get('/robots.txt')
    assert r.status_code == 200
    assert b'User-agent: *' in r.content


class MockClient:
    def __init__(self, *args, **kwargs):
        pass

    def download_file(self, Bucket, Key, Filename):
        with open(Key) as f:
            content = f.read()
        new_dir = '/'.join(Filename.split('/')[:-1])
        try:
            os.makedirs(new_dir)
        except FileExistsError:
            pass
        with open(Filename, 'w+') as f:
            f.write(content)

    def put_object_tagging(self, **kwargs):
        pass


def test_check_no_sig(client):
    r = client.post('/check/', json={'bucket': 'aws_bucket', 'key': str(Path('files/clean_file'))})
    assert r.status_code == 422


def test_check_wrong_sig(client):
    r = client.post(
        '/check/', json={'bucket': 'aws_bucket', 'key': str(Path('files/clean_file')), 'signature': 'wrong'}
    )
    assert r.status_code == 403


def test_check_clean_file(client, monkeypatch):
    monkeypatch.setattr(boto3, 'client', MockClient)
    payload = {'bucket': 'aws_bucket', 'key': 'tests/files/clean_file'}
    sig = hmac.new(settings.shared_secret_key.encode(), json.dumps(payload).encode(), hashlib.sha1).hexdigest()
    r = client.post('/check/', json={'signature': sig, **payload})
    assert r.status_code == 200
    assert r.json() == {'status': 'clean'}


def test_check_infected_file(client, monkeypatch):
    monkeypatch.setattr(boto3, 'client', MockClient)
    payload = {'bucket': 'aws_bucket', 'key': 'tests/files/infected_file'}
    sig = hmac.new(settings.shared_secret_key.encode(), json.dumps(payload).encode(), hashlib.sha1).hexdigest()
    r = client.post('/check/', json={'signature': sig, **payload})
    assert r.status_code == 200
    assert r.json() == {'status': 'infected'}


@patch('src.app.main.os.remove')
def test_check_removed_file(mock_remove, client, monkeypatch):
    monkeypatch.setattr(boto3, 'client', MockClient)
    with patch('os.remove') as mock_remove:
        mock_remove.side_effect = FileNotFoundError
        payload = {'bucket': 'aws_bucket', 'key': 'tests/files/not_found_file'}
        sig = hmac.new(settings.shared_secret_key.encode(), json.dumps(payload).encode(), hashlib.sha1).hexdigest()
        r = client.post('/check/', json={'signature': sig, **payload})
        assert r.status_code == 200
        assert r.json() == {'status': 'File not found'}


class TagFailingDeletedClient(MockClient):
    def put_object_tagging(self, **kwargs):
        raise ClientError(
            {'Error': {'Code': 'MethodNotAllowed', 'Message': 'not allowed'}},
            'PutObjectTagging',
        )

    def head_object(self, **kwargs):
        raise ClientError({'Error': {'Code': 'NoSuchKey', 'Message': 'gone'}}, 'HeadObject')


class TagFailingExistingClient(TagFailingDeletedClient):
    def head_object(self, **kwargs):
        return {'ContentLength': 1}


class MockCleanRun:
    def __init__(self, *args, **kwargs):
        file_path = args[0].rsplit(' ', 1)[-1]
        self.stdout = f'{file_path}: OK\n'.encode()


def test_check_tag_fails_object_deleted(client, monkeypatch):
    monkeypatch.setattr(boto3, 'client', TagFailingDeletedClient)
    monkeypatch.setattr(subprocess, 'run', MockCleanRun)
    payload = {'bucket': 'aws_bucket', 'key': 'tests/files/clean_file'}
    sig = hmac.new(settings.shared_secret_key.encode(), json.dumps(payload).encode(), hashlib.sha1).hexdigest()
    r = client.post('/check/', json={'signature': sig, **payload})
    assert r.status_code == 200
    assert r.json() == {'status': 'clean-untagged'}


def test_check_tag_fails_object_exists_reraises(client, monkeypatch):
    monkeypatch.setattr(boto3, 'client', TagFailingExistingClient)
    monkeypatch.setattr(subprocess, 'run', MockCleanRun)
    payload = {'bucket': 'aws_bucket', 'key': 'tests/files/clean_file'}
    sig = hmac.new(settings.shared_secret_key.encode(), json.dumps(payload).encode(), hashlib.sha1).hexdigest()
    with pytest.raises(ClientError, match='MethodNotAllowed'):
        client.post('/check/', json={'signature': sig, **payload})


class MockRun:
    def __init__(self, *args, **kwargs):
        self.stdout = b''


class MockSubprocessResult:
    def __init__(self, returncode):
        self.returncode = returncode
        self.stdout = b''
        self.stderr = b''


def test_health_ok(client, monkeypatch):
    monkeypatch.setattr(subprocess, 'run', lambda *a, **k: MockSubprocessResult(0))
    r = client.get('/health/')
    assert r.status_code == 200
    assert r.json() == {'status': 'ok'}


def test_health_clamd_down(client, monkeypatch):
    monkeypatch.setattr(subprocess, 'run', lambda *a, **k: MockSubprocessResult(2))
    r = client.get('/health/')
    assert r.status_code == 503


def test_check_error_file(client, monkeypatch):
    monkeypatch.setattr(boto3, 'client', MockClient)
    monkeypatch.setattr(subprocess, 'run', MockRun)
    payload = {'bucket': 'aws_bucket', 'key': 'tests/files/clean_file'}
    sig = hmac.new(settings.shared_secret_key.encode(), json.dumps(payload).encode(), hashlib.sha1).hexdigest()
    r = client.post('/check/', json={'signature': sig, **payload})
    assert r.status_code == 200
    assert r.json() == {'status': 'error'}
