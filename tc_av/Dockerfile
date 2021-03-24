FROM python:3.8-alpine

RUN apk --update --no-cache add unrar-free gcc g++ musl-dev zlib-dev libuv clamav clamav-daemon libffi-dev bash \
 && rm -rf /var/cache/apk/* \
 && rm /bin/sh && ln -s /bin/bash /bin/sh

ADD ./requirements.txt /home/app/requirements.txt
RUN pip install -r /home/app/requirements.txt

ADD ./app /home/root/app
ADD run.py /home/root/run.py

ENV PYTHONUNBUFFERED 1
WORKDIR /home/root
CMD ["python",  "./run.py"]
