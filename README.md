## TutorCruncher virus checker

TutorCruncher's service for checking uploaded documents with [ClamAV](https://www.clamav.net/), built with 
[FastAPI](https://fastapi.tiangolo.com/).

## How it works

ClamAV starts with it's multi-threaded daemon `clamav-daemon`. We then use `clamdscan` to scan files for viruses. 
Updates are run automatically by the service `clamav-freshclam`.
