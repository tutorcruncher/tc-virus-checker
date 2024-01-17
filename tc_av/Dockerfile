FROM clamav/clamav:latest

# Install python/pip
RUN apk add python3 py3-pip gcc musl-dev
RUN pip install --no-cache --upgrade --break-system-packages pip setuptools

add requirements.txt /home/root/requirements.txt
run pip install -r /home/root/requirements.txt --break-system-packages

add ./app /home/root/app
add ./run.py /home/root/run.py

ENV PYTHONUNBUFFERED 1
workdir /home/root
cmd ["python3", "./run.py"]
