from typing import Optional

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file='.env', extra='ignore')

    shared_secret_key: Optional[str] = None
    raven_dsn: Optional[str] = None
    sentry_dsn: Optional[str] = None
    logfire_token: Optional[str] = None
    environment: str = 'dev'
    aws_access_key_id: Optional[str] = None
    aws_secret_access_key: Optional[str] = Field(default=None, alias='AWS_SECRET_KEY')
    live: bool = False
