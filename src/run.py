import os
import subprocess

import uvicorn
from app.logs import setup_logging
from app.main import tc_av_app


def start_clamd():
    os.replace('clamd.conf', '/etc/clamav/clamd.conf')
    output = subprocess.run('clamd', shell=True, stdout=subprocess.PIPE)
    print('Starting clamd...', output.stdout.decode())
    output = subprocess.run('freshclam', shell=True, stdout=subprocess.PIPE)
    print('Running freshclam...', output.stdout.decode())


if __name__ == '__main__':
    setup_logging()
    start_clamd()
    port = int(os.getenv('PORT', 8000))
    uvicorn.run(tc_av_app, host='0.0.0.0', port=port)
