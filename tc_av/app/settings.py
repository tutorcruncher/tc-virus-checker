from typing import Optional

from pydantic import BaseSettings


class Settings(BaseSettings):
    tc_secret_key: Optional[str] = None
    raven_dsn: Optional[str] = None
    aws_access_key_id: Optional[str] = None
    aws_secret_access_key: Optional[str] = None

    class Config:
        fields = {
            'tc_secret_key': {'env': 'TC_SECRET_KEY'},
            'raven_dsn': {'env': 'RAVEN_DSN'},
            'aws_access_key_id': {'env': 'AWS_ACCESS_KEY_ID'},
            'aws_secret_access_key': {'env': 'AWS_SECRET_ACCESS_KEY'},
        }
