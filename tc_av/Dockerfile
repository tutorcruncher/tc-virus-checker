FROM heroku/heroku:18.v16

WORKDIR /root/
ADD install.sh install.sh
RUN bash install.sh

RUN useradd -ms /bin/bash clamav
USER clamav

ADD ./requirements.txt /home/app/requirements.txt
RUN pip install -r /home/app/requirements.txt

ADD ./app /home/clamav/app
ADD run.py /home/clamav/run.py

ENV PYTHONUNBUFFERED 1
WORKDIR /home/clamav
CMD ["python", "./run.py"]
