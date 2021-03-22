## TutorCruncher virus checker

TutorCruncher's service for checking uploaded documents with [ClamAV](https://www.clamav.net/), built with 
[FastAPI](https://fastapi.tiangolo.com/).

## How it works

ClamAV starts with it's multi-threaded daemon `clamav-daemon`. We then use `clamdscan` to scan files for viruses. 
Updates are run automatically by the service `clamav-freshclam`.

The endpoint `/check/` takes arguments for an AWS S3 bucket name and key, which are signed by a shared secret key. This 
app will get the object using the env variables for your AWS keys and check it against the virus database. A response 
will be given for the status of the file, and it will be tagged in AWS.

## Running the app locally

Set your environment variables seen in `tc_av/app/settings.py`, change directory to `tc_av/` and run `python run.py`.

## Running the app on Heroku

We deploy with Heroku, so there's a prebuilt `heroku.yml` file you can use.
