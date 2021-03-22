import pytest
from starlette.testclient import TestClient

from tc_av.app.main import settings


@pytest.fixture
def test_settings(monkeypatch):
    monkeypatch.setattr(settings, 'shared_secret_key', 'test_tc_api_key')
    monkeypatch.setattr(settings, 'aws_access_key_id', 'test_aws_access_key')
    monkeypatch.setattr(settings, 'aws_secret_access_key', 'test_aws_secret_secret')


@pytest.fixture
def client(test_settings):
    from tc_av.app.main import tc_av_app

    yield TestClient(tc_av_app)
