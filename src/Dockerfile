FROM heroku/heroku:22

# Install python/pip
RUN apt-get update && apt-get install -y python3 python3-pip

RUN apt-get install clamav clamav-daemon clamav-freshclam clamav-unofficial-sigs -y

add requirements.txt /home/root/requirements.txt

run pip3 install -r /home/root/requirements.txt

add ./app /home/root/app

add ./run.py /home/root/run.py

add ./clamd.conf /home/root/clamd.conf

RUN mv /home/root/clamd.conf /etc/clamav/clamd.conf

ENV PYTHONUNBUFFERED 1
workdir /home/root
cmd ["python3", "./run.py"]
