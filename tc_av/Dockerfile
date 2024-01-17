FROM clamav/clamav:latest

# Install python/pip
ENV PYTHONUNBUFFERED=1
RUN apk add python3 py3-pip gcc musl-dev
RUN pip install --no-cache --upgrade --break-system-packages pip setuptools

add requirements.txt /app/requirements.txt
run pip install -r /app/requirements.txt --break-system-packages

add ./app /app
add ./run.py /app/run.py

workdir /app
cmd ["python3", "run.py"]
