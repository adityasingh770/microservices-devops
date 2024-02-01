FROM python:3.11-slim-bullseye

RUN apt-get update \
    && apt-get install -y --no-install-recommends --no-install-suggests \
    python3-dev build-essential ffmpeg gcc pkg-config \
    && pip install --no-cache-dir --upgrade pip

WORKDIR /app

COPY ./requirements.txt /app

RUN pip3 install --no-cache-dir --requirement /app/requirements.txt

COPY . /app

CMD ["python3", "consumer.py"]