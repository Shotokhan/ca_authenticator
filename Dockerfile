FROM python:3.9

WORKDIR /usr/src/app

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY *.py ./
COPY run.sh ./
COPY volume/ ./volume/
COPY static/ ./static/
COPY test/ ./test/

# RUN apt-get update -y
# RUN apt-get install -y tcpdump

RUN chmod +x run.sh

CMD ["./run.sh"]
