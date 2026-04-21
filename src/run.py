import os

import uvicorn

from src.app.main import tc_av_app

if __name__ == '__main__':
    port = int(os.getenv('PORT', 8000))
    uvicorn.run(tc_av_app, host='0.0.0.0', port=port)
