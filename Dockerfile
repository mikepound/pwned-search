FROM python:3

RUN pip install requests

ADD . /app

ENTRYPOINT [ "python", "/app/pwned.py" ]
