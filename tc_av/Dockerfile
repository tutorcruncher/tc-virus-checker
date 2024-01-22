FROM clamav/clamav-debian:1.2.0

# Install python/pip
RUN apt-get update && apt-get install -y python3 python3-pip

add requirements.txt /home/root/requirements.txt

run pip3 install -r /home/root/requirements.txt

add ./app /home/root/app

add ./run.py /home/root/run.py

ENV PYTHONUNBUFFERED 1
workdir /home/root
cmd ["python3", "./run.py"]
