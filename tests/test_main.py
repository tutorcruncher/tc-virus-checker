import hashlib
import hmac
import json
import os
from pathlib import Path

from tc_av.app.main import s3_client, settings


def test_index(client):
    r = client.get('/')
    assert r.status_code == 200
    assert r.json() == {'message': "Welcome to TutorCruncher's virus checker"}


def download_file(Bucket, Key, Filename):
    with open(Key) as f:
        content = f.read()
    new_dir = '/'.join(Filename.split('/')[:-1])
    try:
        os.makedirs(new_dir)
    except FileExistsError:
        pass
    with open(Filename, 'w+') as f:
        f.write(content)


def put_object_tagging(**kwargs):
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
    monkeypatch.setattr(s3_client, 'download_file', download_file)
    monkeypatch.setattr(s3_client, 'put_object_tagging', put_object_tagging)
    payload = {'bucket': 'aws_bucket', 'key': 'tests/files/clean_file'}
    sig = hmac.new(settings.tc_secret_key.encode(), json.dumps(payload).encode(), hashlib.sha1).hexdigest()
    r = client.post('/check/', json={'signature': sig, **payload})
    assert r.status_code == 200
    assert r.json() == {'message': 'OK'}


def test_check_infected_file(client, monkeypatch):
    monkeypatch.setattr(s3_client, 'download_file', download_file)
    monkeypatch.setattr(s3_client, 'put_object_tagging', put_object_tagging)
    payload = {'bucket': 'aws_bucket', 'key': 'tests/files/infected_file'}
    sig = hmac.new(settings.tc_secret_key.encode(), json.dumps(payload).encode(), hashlib.sha1).hexdigest()
    r = client.post('/check/', json={'signature': sig, **payload})
    assert r.status_code == 200
    assert r.json() == {'message': 'Virus found'}
