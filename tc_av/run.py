import os
import subprocess

import uvicorn
from app.logs import setup_logging
from app.main import tc_av_app


def start_clamd():
    subprocess.Popen(['clamd'])
    subprocess.Popen(['freshclam'])


if __name__ == '__main__':
    setup_logging()
    start_clamd()
    port = int(os.getenv('PORT', 8000))
    uvicorn.run(tc_av_app, host='0.0.0.0', port=port)
