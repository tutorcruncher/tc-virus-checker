FROM python:3.9-alpine

RUN apk --update --no-cache add gcc g++ musl-dev zlib-dev libuv cffi \
 && apt-get clamav clamav-daemon
 && rm -rf /var/cache/apk/*

ADD ./requirements.txt /home/root/requirements.txt
RUN pip install -r /home/root/requirements.txt

ADD ./app /home/root/app
ADD ./run.py /home/root/run.py

ENV PYTHONUNBUFFERED 1
WORKDIR /home/root
CMD ["python ./run.py"]
