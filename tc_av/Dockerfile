FROM heroku/heroku:18.v16

WORKDIR /root/
ADD install.sh install.sh
RUN bash install.sh

ADD ./requirements.txt /home/app/requirements.txt
RUN pip install -r /home/app/requirements.txt

ADD ./app /home/root/app
ADD run.py /home/root/run.py

ENV PYTHONUNBUFFERED 1
WORKDIR /home/root
CMD ["python",  "./run.py"]
