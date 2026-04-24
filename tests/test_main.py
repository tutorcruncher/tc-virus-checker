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


def _sign(payload: dict) -> str:
    return hmac.new(settings.shared_secret_key.encode(), json.dumps(payload).encode(), hashlib.sha1).hexdigest()


def _post_check(client, payload: dict):
    return client.post('/check/', json={'signature': _sign(payload), **payload})


class MockRun:
    """Drop-in for subprocess.run. Pass stdout/returncode to control the call result."""

    def __init__(self, stdout: bytes = b'', returncode: int = 0):
        self._stdout = stdout
        self._returncode = returncode

    def __call__(self, cmd, *args, **kwargs):
        self.cmd = cmd
        self.stdout = self._stdout
        self.stderr = b''
        self.returncode = self._returncode
        return self


class MockClamdClean:
    """Mimics a clamd scan that reports the file is clean."""

    def __call__(self, cmd, *args, **kwargs):
        # cmd is a list; the last element is the file path
        file_path = cmd[-1]
        self.stdout = f'{file_path}: OK\n'.encode()
        self.stderr = b''
        self.returncode = 0
        return self


class MockClient:
    def __init__(self, *args, **kwargs):
        pass

    def download_file(self, Bucket, Key, Filename):
        with open(Key) as f:
            content = f.read()
        os.makedirs(os.path.dirname(Filename), exist_ok=True)
        with open(Filename, 'w+') as f:
            f.write(content)

    def put_object_tagging(self, **kwargs):
        pass


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


def test_index(client):
    r = client.get('/')
    assert r.status_code == 200
    assert r.json() == {'message': "Welcome to TutorCruncher's virus checker"}


def test_robots(client):
    r = client.get('/robots.txt')
    assert r.status_code == 200
    assert b'User-agent: *' in r.content


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
    r = _post_check(client, {'bucket': 'aws_bucket', 'key': 'tests/files/clean_file'})
    assert r.status_code == 200
    assert r.json() == {'status': 'clean'}


def test_check_infected_file(client, monkeypatch):
    monkeypatch.setattr(boto3, 'client', MockClient)
    r = _post_check(client, {'bucket': 'aws_bucket', 'key': 'tests/files/infected_file'})
    assert r.status_code == 200
    assert r.json() == {'status': 'infected'}


@patch('src.app.main.os.remove')
def test_check_removed_file(mock_remove, client, monkeypatch):
    monkeypatch.setattr(boto3, 'client', MockClient)
    with patch('os.remove') as mock_remove:
        mock_remove.side_effect = FileNotFoundError
        r = _post_check(client, {'bucket': 'aws_bucket', 'key': 'tests/files/not_found_file'})
        assert r.status_code == 200
        assert r.json() == {'status': 'File not found'}


def test_check_tag_fails_object_deleted(client, monkeypatch):
    monkeypatch.setattr(boto3, 'client', TagFailingDeletedClient)
    monkeypatch.setattr(subprocess, 'run', MockClamdClean())
    r = _post_check(client, {'bucket': 'aws_bucket', 'key': 'tests/files/clean_file'})
    assert r.status_code == 200
    assert r.json() == {'status': 'clean-untagged'}


def test_check_tag_fails_object_exists_reraises(client, monkeypatch):
    monkeypatch.setattr(boto3, 'client', TagFailingExistingClient)
    monkeypatch.setattr(subprocess, 'run', MockClamdClean())
    payload = {'bucket': 'aws_bucket', 'key': 'tests/files/clean_file'}
    with pytest.raises(ClientError, match='MethodNotAllowed'):
        client.post('/check/', json={'signature': _sign(payload), **payload})


def test_check_error_file(client, monkeypatch):
    monkeypatch.setattr(boto3, 'client', MockClient)
    monkeypatch.setattr(subprocess, 'run', MockRun(stdout=b''))
    r = _post_check(client, {'bucket': 'aws_bucket', 'key': 'tests/files/clean_file'})
    assert r.status_code == 200
    assert r.json() == {'status': 'error'}


def test_check_timeout(client, monkeypatch):
    monkeypatch.setattr(boto3, 'client', MockClient)

    def fake_run(cmd, *args, **kwargs):
        raise subprocess.TimeoutExpired(cmd, kwargs.get('timeout', 60))

    monkeypatch.setattr(subprocess, 'run', fake_run)
    tag_calls = []
    monkeypatch.setattr(MockClient, 'put_object_tagging', lambda self, **kw: tag_calls.append(kw))
    r = _post_check(client, {'bucket': 'aws_bucket', 'key': 'tests/files/clean_file'})
    assert r.status_code == 200
    assert r.json() == {'status': 'timeout'}
    assert tag_calls == []


def test_health_ok(client, monkeypatch):
    monkeypatch.setattr(subprocess, 'run', MockRun(returncode=0))
    r = client.get('/health/')
    assert r.status_code == 200
    assert r.json() == {'status': 'ok'}


def test_health_clamd_down(client, monkeypatch):
    monkeypatch.setattr(subprocess, 'run', MockRun(returncode=2))
    r = client.get('/health/')
    assert r.status_code == 503
